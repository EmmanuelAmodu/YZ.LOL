package main

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dgrijalva/jwt-go"
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
	Password string `gorm:"column:password;size:256"`
	Email    string `gorm:"column:email;uniqueIndex;size:25;not null"`
	Phone    string `gorm:"column:phone;uniqueIndex;size:20;not null"`
	UserName string `gorm:"column:user_name;uniqueIndex;size:32;not null"`
	Yizz     []Yizz
	Media    []Media
}

type Yizz struct {
	gorm.Model
	ID     uint64 `gorm:"primaryKey"`
	Text   string `gorm:"column:text"`
	UserId uint64 `gorm:"column:user_id;index;not null"`
	Media  []Media
}

type Media struct {
	gorm.Model
	ID     uint64    `gorm:"primaryKey"`
	Type   MediaType `gorm:"type:enum('VIDEO', 'AUDIO', 'IMAGE');column:type"`
	File   string    `gorm:"column:file"`
	UserId uint64    `gorm:"column:user_id;index;not null"`
	YizzID uint64    `gorm:"column:yizz_id;index;not null"`
}

type MediaType string

type contextKey string

const (
	VIDEO MediaType = "VIDEO"
	AUDIO MediaType = "AUDIO"
	IMAGE MediaType = "IMAGE"
)

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

type UserResponseBody struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	UserName string `json:"userName"`
}

type AuthenticateUserRequestBody struct {
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

	db, err := setUpDB()
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
		return
	}

	svc, err := awsSession()
	if err != nil {
		log.Fatalf("failed to connect to aws: %v", err)
		return
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

func setUpDB() (*gorm.DB, error) {
	// Connect to PlanetScale database using DSN environment variable.
	const migrationError = "failed to migrate table"

	db, err := gorm.Open(mysql.Open(os.Getenv("DSN")), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %v", err)
	}

	if err := db.AutoMigrate(&User{}); err != nil {
		return nil, fmt.Errorf(migrationError+" User: %v", err)
	}

	if err := db.AutoMigrate(&Yizz{}); err != nil {
		return nil, fmt.Errorf(migrationError+" table: %v", err)
	}

	if err := db.AutoMigrate(&Media{}); err != nil {
		return nil, fmt.Errorf(migrationError+" Media: %v", err)
	}

	return db, err
}

func awsSession() (*s3.S3, error) {
	// Create a new AWS session.
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)

	if err != nil {
		return nil, err
	}

	// Create S3 service client
	svc := s3.New(sess)

	// check if bucket exists and create if it doesn't
	_, err = svc.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(YizzMediaBucket),
	})

	if err != nil {
		_, err = svc.CreateBucket(&s3.CreateBucketInput{
			Bucket: aws.String(YizzMediaBucket),
		})

		if err != nil {
			return nil, err
		}
	}

	return svc, nil
}

type Handler struct {
	db  *gorm.DB
	svc *s3.S3
}

func NewHandler(db *gorm.DB, svc *s3.S3) http.Handler {
	h := &Handler{db: db, svc: svc}

	router := mux.NewRouter()
	router.HandleFunc("/login", h.login).Methods(http.MethodPost)
	router.Use(addRelevantHeadersMiddleware)
	router.HandleFunc("/user", h.createUser).Methods(http.MethodPost)

	// Add middleware to authenticate requests for routes with /p/ path
	pRouter := router.PathPrefix("/p").Subrouter()
	pRouter.Use(validateTokenMiddleware)

	pRouter.HandleFunc("/user", h.getUserByProfile).Methods(http.MethodGet)
	pRouter.HandleFunc("/user/all", h.getUsers).Methods(http.MethodGet)

	pRouter.HandleFunc("/yizz", h.getYizz).Methods(http.MethodGet)
	pRouter.HandleFunc("/yizz", h.createYizz).Methods(http.MethodPost)
	pRouter.HandleFunc("/yizz/media", h.getMedia).Methods(http.MethodGet)
	pRouter.HandleFunc("/yizz/media", h.uploadMedia).Methods(http.MethodPost)

	return router
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	// Should fetch User from database by username
	var authenticateUserRequestBody AuthenticateUserRequestBody

	if err := json.NewDecoder(r.Body).Decode(&authenticateUserRequestBody); err != nil {
		http.Error(w, InvalidJSONInput, StatusBadRequest)
		return
	}

	// Validate the request body.
	validate = validator.New()
	if err := validate.Struct(&authenticateUserRequestBody); err != nil {
		http.Error(w, InvalidInputData, StatusBadRequest)
		return
	}

	var user User
	h.db.Where(
		"user_name = ? OR email = ? OR phone = ?",
		authenticateUserRequestBody.UserName,
		authenticateUserRequestBody.Email,
		authenticateUserRequestBody.Phone,
	).First(&user)

	if !verifyPassword(authenticateUserRequestBody.Password, user.Password) {
		http.Error(w, "invalid Auth data", http.StatusBadRequest)
		fmt.Println("invalid Auth data")
		return
	}

	token, err := generateToken(user)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	response := UserResponseBody{
		Email:    user.Email,
		Phone:    user.Phone,
		UserName: user.UserName,
	}

	// append token to response header
	w.Header().Set("Authorization", token)

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(response); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) getUserByProfile(w http.ResponseWriter, r *http.Request) {
	// Should fetch User from database by username
	var user User
	h.db.First(&user, "user_name = ?", r.URL.Query()).Select("user_name", "email", "phone")

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(user); err != nil {
		http.Error(w, JsonEncodingFailedError, http.StatusInternalServerError)
	}
}

func (h *Handler) getUsers(w http.ResponseWriter, r *http.Request) {
	// Should fetch User from database
	var user []User
	result := h.db.Find(&user).Select("user_name", "email", "phone")
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

	response := UserResponseBody{
		Email:    user.Email,
		Phone:    user.Phone,
		UserName: user.UserName,
	}

	// Return the created User.
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(response); err != nil {
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

	// Convert the userID to uint64
	userID, err := strconv.ParseUint(fmt.Sprintf("%v", r.Context().Value(contextKey("userID"))), 10, 64)
	if err != nil {
		http.Error(w, "failed to convert userID to uint64", http.StatusInternalServerError)
		return
	}

	// Create a new Yizz in the database.
	yizz := Yizz{Text: body.Text, UserId: userID}
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

	userID, err := strconv.ParseUint(fmt.Sprintf("%v", r.Context().Value(contextKey("userID"))), 10, 64)
	if err != nil {
		http.Error(w, "failed to convert userID to uint64", http.StatusInternalServerError)
		return
	}

	// Create a new media object.
	media := Media{
		Type:   MediaType(r.FormValue("mediaType")),
		File:   handler.Filename,
		UserId: userID,
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
	// Hash the password.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Return the hashed password as a string.
	return string(hash), nil
}

func verifyPassword(password string, hash string) bool {
	// Compare the password with the hash.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}

	// Return true if the password matches the hash.
	return true
}

func addRelevantHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add the Content-Type header.
		w.Header().Set("Content-Type", "application/json")

		// Call the next handler.
		next.ServeHTTP(w, r)
	})
}

func generateToken(user User) (string, error) {
	// Set the expiration time for the token.
	expirationTime := time.Now().Add(24 * time.Hour)

	// Create the claims for the token.
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Issuer:    "yx.lol",
		Subject:   strconv.FormatUint(user.ID, 10),
	}

	// Create the token with the claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with a secret key.
	secretKey := []byte(os.Getenv("JWT_SECRET"))
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	// Return the token as a string.
	return tokenString, nil
}

func validateTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate the token.
		claims, err := validateToken(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set the user ID in the request context.
		r = r.WithContext(setUserIDInContext(r.Context(), claims.Subject))

		// Call the next handler.
		next.ServeHTTP(w, r)
	})
}

func setUserIDInContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, contextKey("userID"), userID)
}

func validateToken(tokenString string) (*jwt.StandardClaims, error) {
	// Parse the token.
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, err
	}

	// Return the claims.
	return token.Claims.(*jwt.StandardClaims), nil
}
