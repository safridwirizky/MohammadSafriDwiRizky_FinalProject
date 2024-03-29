package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
)

var (
	db  *gorm.DB
	err error
)

type User struct {
	ID           uint          `gorm:"primary_key" json:"id"`
	Username     string        `gorm:"unique_index" json:"username" binding:"required"`
	Email        string        `gorm:"unique_index" json:"email" binding:"required,email"`
	Password     string        `json:"-" binding:"required,min=6"`
	Age          int           `json:"age" binding:"required,min=8"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	Photos       []Photo       `json:"photos"`
	Comments     []Comment     `json:"comments"`
	SocialMedias []SocialMedia `json:"social_medias"`
}

type Photo struct {
	ID        uint      `gorm:"primary_key" json:"id"`
	Title     string    `json:"title" binding:"required"`
	Caption   string    `json:"caption"`
	PhotoURL  string    `json:"photo_url" binding:"required"`
	UserID    uint      `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"user"`
}

type Comment struct {
	ID        uint      `gorm:"primary_key" json:"id"`
	UserID    uint      `json:"user_id"`
	PhotoID   uint      `json:"photo_id"`
	Message   string    `json:"message" binding:"required"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      User      `json:"user"`
	Photo     Photo     `json:"photo"`
}

type SocialMedia struct {
	ID             uint      `gorm:"primary_key" json:"id"`
	Name           string    `json:"name" binding:"required"`
	SocialMediaURL string    `json:"social_media_url" binding:"required"`
	UserID         uint      `json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	User           User      `json:"user"`
}

type JWTClaims struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

func main() {
	// Inisialisasi router Gin
	router := gin.Default()

	// Koneksi ke database PostgreSQL
	db, err = gorm.Open("postgres", "host=localhost port=5432 user=postgres dbname=mygram_db password=123 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// AutoMigrate tabel-tabel
	db.AutoMigrate(&User{}, &Photo{}, &Comment{}, &SocialMedia{})

	// Inisialisasi rute-rute
	initRoutes(router)

	// Menjalankan server pada port 8080
	router.Run(":8080")
}

func initRoutes(router *gin.Engine) {
	// Rute untuk registrasi dan login user
	router.POST("/users/register", registerUser)
	router.POST("/users/login", loginUser)

	// Rute yang memerlukan autentikasi dan otorisasi
	authenticated := router.Group("/")
	authenticated.Use(authMiddleware)
	{
		authenticated.GET("/photos", getPhotos)
		authenticated.POST("/photos", createPhoto)
		authenticated.PUT("/photos/:photoID", updatePhoto)
		authenticated.DELETE("/photos/:photoID", deletePhoto)

		// Tambahan rute untuk komentar dan social media
		authenticated.POST("/comments", createComment)
		authenticated.GET("/comments", getComments)
		authenticated.PUT("/comments/:commentID", updateComment)
		authenticated.DELETE("/comments/:commentID", deleteComment)

		authenticated.POST("/socialmedias", createSocialMedia)
		authenticated.GET("/socialmedias", getSocialMedias)
		authenticated.PUT("/socialmedias/:socialMediaID", updateSocialMedia)
		authenticated.DELETE("/socialmedias/:socialMediaID", deleteSocialMedia)
	}
}

// Middleware untuk autentikasi
func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token is required"})
		c.Abort()
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("1234567890"), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	c.Set("user_id", claims.UserID)
	c.Next()
}

// Handler untuk registrasi user
func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password sebelum disimpan
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	// Simpan user ke database
	db.Create(&user)
	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

// Handler untuk login user
func loginUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Dapatkan user dari database berdasarkan email
	var dbUser User
	if err := db.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Periksa password dengan hashing
	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Buat token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		UserID: dbUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token berlaku selama 1 hari
		},
	})

	tokenString, err := token.SignedString([]byte("1234567890"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Handler untuk mendapatkan daftar foto
func getPhotos(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var photos []Photo
	db.Where("user_id = ?", userID).Find(&photos)

	c.JSON(http.StatusOK, photos)
}

// Handler untuk membuat foto baru
func createPhoto(c *gin.Context) {
	var photo Photo
	if err := c.ShouldBindJSON(&photo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	photo.UserID = userID.(uint)

	db.Create(&photo)
	c.JSON(http.StatusCreated, photo)
}

// Handler untuk mengupdate foto
func updatePhoto(c *gin.Context) {
	photoID := c.Param("photoID")
	var photo Photo
	if err := db.Where("id = ?", photoID).First(&photo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Photo not found"})
		return
	}

	var updatedPhoto Photo
	if err := c.ShouldBindJSON(&updatedPhoto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Model(&photo).Updates(updatedPhoto)
	c.JSON(http.StatusOK, gin.H{"message": "Photo updated successfully"})
}

// Handler untuk menghapus foto
func deletePhoto(c *gin.Context) {
	photoID := c.Param("photoID")
	var photo Photo
	if err := db.Where("id = ?", photoID).First(&photo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Photo not found"})
		return
	}

	db.Delete(&photo)
	c.JSON(http.StatusOK, gin.H{"message": "Photo deleted successfully"})
}

// Handler untuk membuat komentar baru
func createComment(c *gin.Context) {
	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	comment.UserID = userID.(uint)

	db.Create(&comment)
	c.JSON(http.StatusCreated, comment)
}

// Handler untuk mendapatkan daftar komentar
func getComments(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var comments []Comment
	db.Where("user_id = ?", userID).Find(&comments)

	c.JSON(http.StatusOK, comments)
}

// Handler untuk mengupdate komentar
func updateComment(c *gin.Context) {
	commentID := c.Param("commentID")
	var comment Comment
	if err := db.Where("id = ?", commentID).First(&comment).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Comment not found"})
		return
	}

	var updatedComment Comment
	if err := c.ShouldBindJSON(&updatedComment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Model(&comment).Updates(updatedComment)
	c.JSON(http.StatusOK, gin.H{"message": "Comment updated successfully"})
}

// Handler untuk menghapus komentar
func deleteComment(c *gin.Context) {
	commentID := c.Param("commentID")
	var comment Comment
	if err := db.Where("id = ?", commentID).First(&comment).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Comment not found"})
		return
	}

	db.Delete(&comment)
	c.JSON(http.StatusOK, gin.H{"message": "Comment deleted successfully"})
}

// Handler untuk membuat social media baru
func createSocialMedia(c *gin.Context) {
	var socialMedia SocialMedia
	if err := c.ShouldBindJSON(&socialMedia); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	socialMedia.UserID = userID.(uint)

	db.Create(&socialMedia)
	c.JSON(http.StatusCreated, socialMedia)
}

// Handler untuk mendapatkan daftar social media
func getSocialMedias(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var socialMedias []SocialMedia
	db.Where("user_id = ?", userID).Find(&socialMedias)

	c.JSON(http.StatusOK, socialMedias)
}

// Handler untuk mengupdate social media
func updateSocialMedia(c *gin.Context) {
	socialMediaID := c.Param("socialMediaID")
	var socialMedia SocialMedia
	if err := db.Where("id = ?", socialMediaID).First(&socialMedia).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Social media not found"})
		return
	}

	var updatedSocialMedia SocialMedia
	if err := c.ShouldBindJSON(&updatedSocialMedia); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Model(&socialMedia).Updates(updatedSocialMedia)
	c.JSON(http.StatusOK, gin.H{"message": "Social media updated successfully"})
}

// Handler untuk menghapus social media
func deleteSocialMedia(c *gin.Context) {
	socialMediaID := c.Param("socialMediaID")
	var socialMedia SocialMedia
	if err := db.Where("id = ?", socialMediaID).First(&socialMedia).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Social media not found"})
		return
	}

	db.Delete(&socialMedia)
	c.JSON(http.StatusOK, gin.H{"message": "Social media deleted successfully"})
}
