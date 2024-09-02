package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
)

type CreateSignatureDeviceSchema struct {
	// TODO: check if i have to add the id here (read the specs)
	Algorithm string `json:"algorithm"`
	Label     string `json:"label"`
}

type CreateSignatureDeviceResponse struct {
	ID uuid.UUID `json:"id"`
}

type SignTransactionSchema struct {
	DeviceID uuid.UUID `json:"deviceId"`
	Data     string    `json:"data"`
}

type SignTransactionResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		log.Printf("Invalid method: %s on %s", request.Method, request.URL.Path)
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	var reqData CreateSignatureDeviceSchema
	if err := json.NewDecoder(request.Body).Decode(&reqData); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			http.StatusText(http.StatusBadRequest),
		})
		return
	}

	id, err := s.signatureService.NewSignatureDevice(reqData.Algorithm, reqData.Label)
	if err != nil {
		log.Printf("Failed to create signature device: %v", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{"Failed to create signature device"})
		return
	}

	respData := CreateSignatureDeviceResponse{
		ID: id,
	}

	WriteAPIResponse(response, http.StatusOK, respData)
	log.Printf("Successfuly created device %v", id)
}

// TODO: could use some decorators to avoid duplicated code
func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		log.Printf("Invalid method: %s on %s", request.Method, request.URL.Path)
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	var reqData SignTransactionSchema
	if err := json.NewDecoder(request.Body).Decode(&reqData); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			http.StatusText(http.StatusBadRequest),
		})
		return
	}

	signature, signData, err := s.signatureService.SignData(reqData.DeviceID, reqData.Data)
	if err != nil {
		log.Printf("Failed to sign data: %v", err)
		WriteErrorResponse(response, http.StatusInternalServerError, []string{"Failed to sign data"})
		return
	}

	respData := SignTransactionResponse{
		Signature:  signature,
		SignedData: signData,
	}
	WriteAPIResponse(response, http.StatusOK, respData)
	log.Print("Successfuly signed data")
}

type ListDevicesResponse struct {
	ID        uuid.UUID `json:"id"`
	Label     string    `json:"label"`
	Algorithm string    `json:"algorithm"`
	Counter   int       `json:"signature_counter"`
}

func (s *Server) ListDevices(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		log.Printf("Invalid method: %s on %s", request.Method, request.URL.Path)
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	devices := s.signatureService.GetDevices()

	respData := make([]ListDevicesResponse, 0)
	for _, device := range devices {
		respData = append(respData, ListDevicesResponse(device))
	}
	WriteAPIResponse(response, http.StatusOK, respData)
	log.Print("Successfuly listed devices")
}
