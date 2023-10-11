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
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var validate *validator.Validate

type User struct {
	gorm.Model
	ID       uint64 `gorm:"primaryKey"`
	Password string `gorm:"column:password"`
	Yizz     []Yizz
	Media    []Media
	Email    string `gorm:"column:email"`
	Phone    string `gorm:"column:phone"`
	UserName string `gorm:"column:userName;UNIQUE_INDEX:compositeindex;index;not null"`
}

type Yizz struct {
	gorm.Model
	ID     uint64 `gorm:"primaryKey"`
	Text   string `gorm:"column:text"`
	UserId uint64 `gorm:"column:userId;index;not null"`
	Media  []Media
}

type Media struct {
	gorm.Model
	ID     uint64    `gorm:"primaryKey"`
	Type   MediaType `gorm:"type:enum('VIDEO', 'AUDIO', 'IMAGE');column:type"`
	File   string    `gorm:"column:file"`
	UserId uint64    `gorm:"column:userId;index;not null"`
	YizzID uint64    `gorm:"column:yizzId;index;not null"`
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
}

type CreateUserRequestBody struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	UserName string `json:"userName"`
}

const (
	StatusCreated           = http.StatusCreated
	StatusBadRequest        = http.StatusBadRequest
	StatusServerError       = http.StatusInternalServerError
	InvalidJSONInput        = "Invalid JSON input"
	InvalidInputData        = "Invalid input data"
	DatabaseCreateError     = "Database create error"
	JsonEncodingFailedError = "Json Encoding Failed"
	YizzMediaBucket         = "yizz-media"
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

	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatalf("failed to migrate User table")
		return
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

	// check if bucket exists and create if it doesn't
	_, err = svc.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(YizzMediaBucket),
	})

	if err != nil {
		_, err = svc.CreateBucket(&s3.CreateBucketInput{
			Bucket: aws.String(YizzMediaBucket),
		})

		if err != nil {
			log.Fatalf("failed to create bucket")
			return
		}
	}

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
	r.HandleFunc("/user", h.getUserByProfile).Methods(http.MethodGet)
	r.HandleFunc("/user/all", h.getUsers).Methods(http.MethodGet)
	r.HandleFunc("/user", h.createUser).Methods(http.MethodPost)

	r.HandleFunc("/yizz", h.getYizz).Methods(http.MethodGet)
	r.HandleFunc("/yizz", h.createYizz).Methods(http.MethodPost)

	r.HandleFunc("/media", h.getMedia).Methods(http.MethodGet)
	r.HandleFunc("/media", h.uploadMedia).Methods(http.MethodPost)

	return r
}

func (h *Handler) getUserByProfile(w http.ResponseWriter, r *http.Request) {
	// Should fetch User from database by username
	var user User
	h.db.First(&user, "user_name = ?", r.URL.Query().Get("userName"))
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) getUsers(w http.ResponseWriter, r *http.Request) {
	// Should fetch User from database
	var user []User
	result := h.db.Find(&user)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Return the fetched User.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var createUserRequestBody CreateUserRequestBody
	// Decode the request body into a struct.
	if err := json.NewDecoder(r.Body).Decode(&createUserRequestBody); err != nil {
		http.Error(w, InvalidJSONInput, StatusBadRequest)
		return
	}

	// Validate the request body.
	validate = validator.New()
	if err := validate.Struct(&createUserRequestBody); err != nil {
		http.Error(w, InvalidInputData, StatusBadRequest)
		return
	}

	// hash password
	hashPassword, err := hashPassword(createUserRequestBody.Password)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	// Create a new User object.
	user := User{
		Password: hashPassword,
		Email:    createUserRequestBody.Email,
		Phone:    createUserRequestBody.Phone,
		UserName: createUserRequestBody.UserName,
	}

	// Create a new User in the database.
	result := h.db.Create(&user)
	if result.Error != nil {
		http.Error(w, DatabaseCreateError, StatusServerError)
		return
	}

	// Return the created User.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
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

func (h *Handler) uploadMedia(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "failed to parse multipart form data", http.StatusBadRequest)
		return
	}

	// Get the file from the request body.
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "failed to get file from request body", http.StatusBadRequest)
		return
	}

	defer file.Close()

	// Upload the file to S3.
	_, err = h.svc.PutObject(&s3.PutObjectInput{
		Bucket: aws.String("yizz-media"),
		Key:    aws.String(handler.Filename),
		Body:   file,
	})

	if err != nil {
		http.Error(w, "failed to upload file to S3", http.StatusInternalServerError)
		return
	}

	// Create a new media object.
	media := Media{
		Type: MediaType(r.FormValue("mediaType")),
		File: handler.Filename,
	}

	// Save the media object to the database.
	result := h.db.Create(&media)
	if result.Error != nil {
		http.Error(w, "failed to save media to database", http.StatusInternalServerError)
		return
	}

	// Return the created media object.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(media); err != nil {
		http.Error(w, "failed to encode media object", http.StatusInternalServerError)
		return
	}
}

func hashPassword(password string) (string, error) {
	// Generate a salt for the hash.
	salt, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Generate the hash for the password.
	hash, err := bcrypt.GenerateFromPassword(salt, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Return the hashed password as a string.
	return string(hash), nil
}
