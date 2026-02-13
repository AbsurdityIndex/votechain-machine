package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
)

type LedgerNodeHandler struct {
	service      *service.LedgerNodeService
	maxBodyBytes int64
}

func NewLedgerNodeHandler(svc *service.LedgerNodeService, maxBodyBytes int64) *LedgerNodeHandler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 8 << 20
	}
	return &LedgerNodeHandler{service: svc, maxBodyBytes: maxBodyBytes}
}

func (h *LedgerNodeHandler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)
	mux.HandleFunc("POST /v1/ledger/append", h.handleAppend)
	mux.HandleFunc("GET /v1/ledger/entries/", h.handleGetEntry)
	return mux
}

func (h *LedgerNodeHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.Health(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "health")
	writeJSON(w, http.StatusOK, resp)
}

func (h *LedgerNodeHandler) handleAppend(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.Header.Get("X-VoteChain-Write-Token"))
	if !h.service.VerifyWriteToken(token) {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: "UNAUTHORIZED", Message: "invalid write token", Retryable: false}})
		return
	}
	var req protocol.LedgerAppendRequest
	if err := decodeJSONLimitedNode(r, h.maxBodyBytes, &req); err != nil {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", err.Error(), false, err))
		return
	}
	resp, err := h.service.Append(r.Context(), req)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "ledger_append")
	logging.AddField(r.Context(), "event_id", req.EventID)
	logging.AddField(r.Context(), "bundle_id", req.BundleID)
	logging.AddField(r.Context(), "entry_index", resp.EntryIndex)
	writeJSON(w, http.StatusOK, resp)
}

func (h *LedgerNodeHandler) handleGetEntry(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/ledger/entries/")), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", "missing entry index", false, nil))
		return
	}
	idx, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || idx <= 0 {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", "invalid entry index", false, err))
		return
	}
	entry, found, err := h.service.GetEntry(r.Context(), idx)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: "NOT_FOUND", Message: "entry not found", Retryable: false}})
		return
	}
	logging.AddField(r.Context(), "op", "ledger_get_entry")
	logging.AddField(r.Context(), "entry_index", idx)
	writeJSON(w, http.StatusOK, entry)
}

func (h *LedgerNodeHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var appErr *service.AppError
	if errors.As(err, &appErr) {
		logging.AddField(r.Context(), "error_code", appErr.Code)
		logging.AddField(r.Context(), "error_message", appErr.Message)
		writeJSON(w, appErr.HTTPStatus, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: appErr.Code, Message: appErr.Message, Retryable: appErr.Retryable}})
		return
	}
	logging.AddField(r.Context(), "error_code", "INTERNAL_ERROR")
	logging.AddField(r.Context(), "error_message", err.Error())
	writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: "INTERNAL_ERROR", Message: "internal server error", Retryable: true}})
}

func decodeJSONLimitedNode(r *http.Request, maxBodyBytes int64, out any) error {
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
