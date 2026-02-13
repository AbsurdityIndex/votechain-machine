package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
)

type IngestHandler struct {
	service      *service.IngestService
	maxBodyBytes int64
}

func NewIngestHandler(svc *service.IngestService, maxBodyBytes int64) *IngestHandler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 << 20
	}
	return &IngestHandler{service: svc, maxBodyBytes: maxBodyBytes}
}

func (h *IngestHandler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)
	mux.HandleFunc("POST /v1/ingest/bundle", h.handleIngestBundle)
	return mux
}

func (h *IngestHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	logging.AddField(r.Context(), "op", "health")
	writeJSON(w, http.StatusOK, h.service.Health(r.Context()))
}

func (h *IngestHandler) handleIngestBundle(w http.ResponseWriter, r *http.Request) {
	var req protocol.IngestBundleRequest
	if err := decodeJSONLimited(r, h.maxBodyBytes, &req); err != nil {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", err.Error(), false, err))
		return
	}
	resp, err := h.service.IngestBundle(r.Context(), req)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "ingest_bundle")
	logging.AddField(r.Context(), "bundle_id", resp.BundleID)
	logging.AddField(r.Context(), "machine_id", resp.MachineID)
	logging.AddField(r.Context(), "election_id", resp.ElectionID)
	logging.AddField(r.Context(), "ingest_status", resp.Status)
	writeJSON(w, http.StatusOK, resp)
}

func (h *IngestHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var appErr *service.AppError
	if errors.As(err, &appErr) {
		logging.AddField(r.Context(), "error_code", appErr.Code)
		logging.AddField(r.Context(), "error_message", appErr.Message)
		writeJSON(w, appErr.HTTPStatus, protocol.ErrorResponse{Error: protocol.ErrorBody{
			Code:      appErr.Code,
			Message:   appErr.Message,
			Retryable: appErr.Retryable,
		}})
		return
	}
	logging.AddField(r.Context(), "error_code", "INTERNAL_ERROR")
	logging.AddField(r.Context(), "error_message", err.Error())
	writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: protocol.ErrorBody{
		Code:      "INTERNAL_ERROR",
		Message:   "internal server error",
		Retryable: true,
	}})
}

func decodeJSONLimited(r *http.Request, maxBodyBytes int64, out any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, maxBodyBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func BearerAuthMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := strings.TrimSpace(r.Header.Get("Authorization"))
			parts := strings.SplitN(hdr, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: protocol.ErrorBody{
					Code:      "UNAUTHORIZED",
					Message:   "missing bearer token",
					Retryable: false,
				}})
				return
			}
			given := strings.TrimSpace(parts[1])
			if subtle.ConstantTimeCompare([]byte(given), []byte(token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: protocol.ErrorBody{
					Code:      "UNAUTHORIZED",
					Message:   "invalid bearer token",
					Retryable: false,
				}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func IPAllowListMiddleware(cidrs []string) (func(http.Handler) http.Handler, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, netw, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, netw)
	}
	if len(nets) == 0 {
		return func(next http.Handler) http.Handler { return next }, nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			if ip == nil {
				writeJSON(w, http.StatusForbidden, protocol.ErrorResponse{Error: protocol.ErrorBody{
					Code:      "FORBIDDEN",
					Message:   "source ip not allowed",
					Retryable: false,
				}})
				return
			}
			allowed := false
			for _, n := range nets {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				writeJSON(w, http.StatusForbidden, protocol.ErrorResponse{Error: protocol.ErrorBody{
					Code:      "FORBIDDEN",
					Message:   "source ip not allowed",
					Retryable: false,
				}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
