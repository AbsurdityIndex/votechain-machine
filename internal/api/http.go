package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
)

type Handler struct {
	service *service.MachineService
	logger  *slog.Logger
}

func NewHandler(svc *service.MachineService, logger *slog.Logger) *Handler {
	return &Handler{service: svc, logger: logger}
}

func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)
	mux.HandleFunc("POST /v1/election/load", h.handleLoadElection)
	mux.HandleFunc("POST /v1/election/challenge", h.handleIssueChallenge)
	mux.HandleFunc("POST /v1/election/cast", h.handleCastBallot)
	mux.HandleFunc("POST /v1/election/verify", h.handleVerifyReceipt)
	mux.HandleFunc("POST /v1/election/close", h.handleClosePolls)
	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.Health(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "health")
	logging.AddField(r.Context(), "ballot_count", resp.BallotCount)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleLoadElection(w http.ResponseWriter, r *http.Request) {
	var req protocol.LoadElectionRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", err.Error(), false, err))
		return
	}
	resp, err := h.service.LoadElection(r.Context(), req)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "load_election")
	logging.AddField(r.Context(), "election_id", resp.ElectionID)
	logging.AddField(r.Context(), "manifest_id", resp.ManifestID)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleIssueChallenge(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.IssueChallenge(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "issue_challenge")
	logging.AddField(r.Context(), "challenge_id", resp.ChallengeID)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleCastBallot(w http.ResponseWriter, r *http.Request) {
	var req protocol.CastBallotRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", err.Error(), false, err))
		return
	}
	resp, err := h.service.CastBallot(r.Context(), req)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "cast_ballot")
	logging.AddField(r.Context(), "receipt_id", resp.CastReceipt.ReceiptID)
	logging.AddField(r.Context(), "tx_id", resp.CastReceipt.Anchor.TxID)
	logging.AddField(r.Context(), "ballot_hash", resp.CastReceipt.BallotHash)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleVerifyReceipt(w http.ResponseWriter, r *http.Request) {
	var req protocol.VerifyReceiptRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, service.NewAppError(http.StatusBadRequest, "BAD_REQUEST", err.Error(), false, err))
		return
	}
	resp, err := h.service.VerifyReceipt(r.Context(), req)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "verify_receipt")
	logging.AddField(r.Context(), "verification_status", resp.Status)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleClosePolls(w http.ResponseWriter, r *http.Request) {
	resp, err := h.service.ClosePolls(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "close_polls")
	logging.AddField(r.Context(), "bundle_path", resp.BundlePath)
	logging.AddField(r.Context(), "bundle_sha256", resp.BundleSHA256)
	logging.AddField(r.Context(), "ballot_count", resp.BallotCount)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
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

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, 2<<20)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
