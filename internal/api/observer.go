package api

import (
	"errors"
	"net/http"

	"github.com/votechain/votechain-machine/internal/logging"
	"github.com/votechain/votechain-machine/internal/protocol"
	"github.com/votechain/votechain-machine/internal/service"
)

type ObserverHandler struct {
	service *service.ObserverService
}

func NewObserverHandler(svc *service.ObserverService) *ObserverHandler {
	return &ObserverHandler{service: svc}
}

func (h *ObserverHandler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)
	mux.HandleFunc("GET /v1/observer/status", h.handleStatus)
	mux.HandleFunc("GET /v1/observer/report", h.handleReport)
	return mux
}

func (h *ObserverHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "health")
	logging.AddField(r.Context(), "overall", status.Overall)
	writeJSON(w, http.StatusOK, map[string]any{
		"service":    status.Service,
		"version":    status.Version,
		"overall":    status.Overall,
		"time":       status.Timestamp,
		"components": map[string]bool{"machine": status.Machine.Healthy, "ingest": status.Ingest.Healthy},
	})
}

func (h *ObserverHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	logging.AddField(r.Context(), "op", "observer_status")
	logging.AddField(r.Context(), "overall", status.Overall)
	logging.AddField(r.Context(), "bundle_count", status.IngestData.BundleCount)
	writeJSON(w, http.StatusOK, status)
}

func (h *ObserverHandler) handleReport(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	report := h.service.MarkdownReport(status)
	logging.AddField(r.Context(), "op", "observer_report")
	logging.AddField(r.Context(), "overall", status.Overall)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(report))
}

func (h *ObserverHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
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
