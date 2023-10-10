package main

import (
	"database/sql/driver"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var validate *validator.Validate

type Yizz struct {
	gorm.Model
	ID   uint64 `gorm:"primaryKey"`
	Text string `gorm:"column:text"`
	// UserId uint64 `gorm:"column:userId"`
	Media []Media
}

type Media struct {
	gorm.Model
	ID     uint64    `gorm:"primaryKey"`
	Type   MediaType `gorm:"type:enum('VIDEO', 'AUDIO', 'IMAGE');column:type"`
	File   string    `gorm:"column:file"`
	YizzID uint64    `gorm:"column:yizzId"`
}

type MediaType string

const (
	VIDEO MediaType = "VIDEO"
	AUDIO MediaType = "AUDIO"
	IMAGE MediaType = "IMAGE"
)

func (ct *MediaType) Scan(value interface{}) error {
	*ct = MediaType(value.([]byte))
	return nil
}

func (ct MediaType) Value() (driver.Value, error) {
	return string(ct), nil
}

type CreateYizzRequestBody struct {
	Text string `json:"text"`
}

type CreateMediaRequestBody struct {
	File      string    `json:"file"`
	MediaType MediaType `json:"mediaType"`
	YizzID    uint64    `json:"yizzId"`
}

const (
	StatusCreated           = http.StatusCreated
	StatusBadRequest        = http.StatusBadRequest
	StatusServerError       = http.StatusInternalServerError
	InvalidJSONInput        = "Invalid JSON input"
	InvalidInputData        = "Invalid input data"
	DatabaseCreateError     = "Database create error"
	JsonEncodingFailedError = "Json Encoding Failed"
)

func main() {
	// Load environment variables from file.
	if err := godotenv.Load(); err != nil {
		log.Fatalf("failed to load environment variables: %v", err)
	}

	// Connect to PlanetScale database using DSN environment variable.
	db, err := gorm.Open(mysql.Open(os.Getenv("DSN")), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		log.Fatalf("failed to connect to PlanetScale: %v", err)
	}

	if err := db.AutoMigrate(&Yizz{}); err != nil {
		log.Fatalf("failed to migrate yizz table")
		return
	}

	if err := db.AutoMigrate(&Media{}); err != nil {
		log.Fatalf("failed to migrate Media table")
		return
	}

	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)

	if err != nil {
		log.Fatalf("failed to create aws session")
		return
	}

	// Create S3 service client
	svc := s3.New(awsSession)

	// Create an API handler which serves data from PlanetScale.
	handler := NewHandler(db, svc)

	// Start an HTTP API server.
	const addr = ":8080"
	log.Printf("successfully connected to PlanetScale, starting HTTP server on %q", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("failed to serve HTTP: %v", err)
	}
}

type Handler struct {
	db  *gorm.DB
	svc *s3.S3
}

func NewHandler(db *gorm.DB, svc *s3.S3) http.Handler {
	h := &Handler{db: db, svc: svc}

	r := mux.NewRouter()
	r.HandleFunc("/yizz", h.getYizz).Methods(http.MethodGet)
	r.HandleFunc("/yizz", h.createYizz).Methods(http.MethodPost)

	r.HandleFunc("/media", h.getMedia).Methods(http.MethodGet)
	r.HandleFunc("/media", h.createMedia).Methods(http.MethodPost)

	return r
}

func (h *Handler) getYizz(w http.ResponseWriter, r *http.Request) {
	// Should fetch Yizz from database
	var yizz []Yizz
	result := h.db.Find(&yizz)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Return the fetched Yizz.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(yizz); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) getMedia(w http.ResponseWriter, r *http.Request) {
	// Should fetch Media from database
	var media []Media
	result := h.db.Find(&media)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Return the fetched Media.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(media); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) createYizz(w http.ResponseWriter, r *http.Request) {
	// Decode the request body into a struct.
	var body CreateYizzRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, InvalidJSONInput, StatusBadRequest)
		return
	}

	// Validate the request body.
	validate = validator.New()
	if err := validate.Struct(&body); err != nil {
		http.Error(w, InvalidInputData, StatusBadRequest)
		return
	}

	// Create a new Yizz in the database.
	yizz := Yizz{Text: body.Text}
	result := h.db.Create(&yizz)
	if result.Error != nil {
		http.Error(w, DatabaseCreateError, StatusServerError)
		return
	}

	// Return the created Yizz.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(yizz); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) createMedia(w http.ResponseWriter, r *http.Request) {
	// Decode the request body into a struct.
	var body CreateMediaRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, InvalidJSONInput, StatusBadRequest)
		return
	}

	// Validate the request body.
	validate = validator.New()
	if err := validate.Struct(&body); err != nil {
		http.Error(w, InvalidInputData, StatusBadRequest)
		return
	}

	media := Media{
		Type:   MediaType(body.MediaType),
		File:   body.File,
		YizzID: body.YizzID,
	}
	result := h.db.Create(&media)
	if result.Error != nil {
		http.Error(w, DatabaseCreateError, StatusServerError)
		return
	}

	// Return the created Yizz.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(media); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}
