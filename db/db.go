package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB
var jwtSecret = []byte("your_secret_key")

type Food struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	ExpiryDate   string `json:"expiry_date"`
	Quantity     int    `json:"quantity"`
	CategoryName string `json:"category_name"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type AddFoodRequest struct {
	Name       string `json:"name"`
	ExpiryDate string `json:"expiry_date"`
	Quantity   int    `json:"quantity"`
	CategoryID int    `json:"category_id"`
}

type RecipeRequest struct {
	FoodID []int `json:"food_id"`
}

type RecipeResponse struct {
	Recipe string `json:"recipe"`
}

func InitDB() {
	_ = godotenv.Load() // Coba load .env, tapi jangan panic kalau gagal

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	DB, err = sql.Open("mysql", databaseURL)
	if err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatalf("Tidak bisa terhubung ke database: %v", err)
	}

	fmt.Println("✅ Berhasil terhubung ke database")
}


func DeleteCategory(userID int, categoryID int) error {
	hasPerm, err := UserHasPermission(userID, "delete_category")
	if err != nil || !hasPerm {
		return fmt.Errorf("tidak punya izin menghapus kategori")
	}

	_, err = DB.Exec("DELETE FROM categories WHERE id = ?", categoryID)
	return err
}

func DeleteFood(id, userID string) error {
	_, err := DB.Exec("DELETE FROM foods WHERE id = ? AND user_id = ?", id, userID)
	return err
}

func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[\w._%+\-]+@[\w.\-]+\.[A-Za-z]{2,}$`)
	return re.MatchString(email)
}

func isValidPassword(password string) bool {
	var hasUpper, hasSymbol bool
	if len(password) < 8 {
		return false
	}
	for _, c := range password {
		if unicode.IsUpper(c) {
			hasUpper = true
		}
		if strings.ContainsRune("!@#$%^&*()_+{}[]:;<>,.?/~`-=", c) {
			hasSymbol = true
		}
	}
	return hasUpper && hasSymbol
}

func GenerateJWT(username string) (string, error) {
	exp := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp.Unix(),
			Issuer:    "savebite",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func UserHasPermission(userID int, perm string) (bool, error) {
	var result bool
	err := DB.QueryRow(`
		SELECT COUNT(*) > 0
		FROM role_permissions rp
		JOIN users u ON u.role_id = rp.role_id 
		JOIN permissions p ON p.id = rp.permission_id
		WHERE u.id = ? AND p.name = ?
	`, userID, perm).Scan(&result)
	return result, err
}

func AddFood(name, expiry string, quantity, userID, catID int) error {
	_, err := DB.Exec(`
		INSERT INTO foods (name, expiry_date, quantity, user_id, category_id) 
		VALUES (?, ?, ?, ?, ?)
	`, name, expiry, quantity, userID, catID)
	return err
}

func AddRecipe(recipe string, foodIDs []int, userID int) error {
	// 1. Cek izin user
	hasPerm, err := UserHasPermission(userID, "add_recipe")
	if err != nil || !hasPerm {
		return fmt.Errorf("unauthorized")
	}

	// 2. Mulai transaksi biar lebih aman
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// 3. Simpan ke tabel food_recipes
	res, err := tx.Exec("INSERT INTO food_recipes (recipe, user_id) VALUES (?, ?)", recipe, userID)
	if err != nil {
		return err
	}

	recipeID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	// 4. Simpan ke tabel recipe_ingredients
	for _, foodID := range foodIDs {
		_, err := tx.Exec("INSERT INTO recipe_ingredients (recipe_id, food_id) VALUES (?, ?)", recipeID, foodID)
		if err != nil {
			return err
		}
	}

	return nil
}

func PromoteUserToRole(requesterID, targetUserID int, roleName string) error {
	hasPerm, err := UserHasPermission(requesterID, "promote_user_to_role")
	if err != nil || !hasPerm {
		return fmt.Errorf("unauthorized to promote user")
	}
	_, err = DB.Exec(`
		UPDATE users 
		SET role_id = (SELECT id FROM roles WHERE name = ?) 
		WHERE id = ?
	`, roleName, targetUserID)
	return err
}

func AddCategory(userID int, categoryName string) error {
	hasPerm, err := UserHasPermission(userID, "add_category")
	if err != nil || !hasPerm {
		return fmt.Errorf("user tidak memiliki izin untuk menambah kategori")
	}
	_, err = DB.Exec("INSERT INTO categories (name) VALUES (?)", categoryName)
	return err
}

func SaveLoginLog(userId, username, ipAddress string) error {
	fmt.Printf("\n=== SaveLoginLog Started ===\n")
	fmt.Printf("Input - UserID: %s, IP: %s\n", userId, ipAddress)

	// Convert userId to int since the database expects an integer
	uid, err := strconv.Atoi(userId)
	if err != nil {
		fmt.Printf("Error converting user_id: %v\n", err)
		return fmt.Errorf("failed to convert user_id to int: %v", err)
	}
	fmt.Printf("Converted UserID to int: %d\n", uid)

	// Note: we don't store username in login_logs table as per the schema
	result, err := DB.Exec("INSERT INTO login_logs (user_id, ip_address) VALUES (?, ?)",
		uid, ipAddress)
	if err != nil {
		fmt.Printf("Error executing query: %v\n", err)
		return fmt.Errorf("database error: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Printf("Error getting rows affected: %v\n", err)
		return fmt.Errorf("error checking result: %v", err)
	}
	fmt.Printf("Rows affected: %d\n", rowsAffected)
	fmt.Printf("=== SaveLoginLog Completed Successfully ===\n\n")
	return nil
}

func GetFoods(userID int) ([]Food, error) {
	rows, err := DB.Query("SELECT food_id, food_name, expiry_date, quantity, category_name FROM view_user_foods WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Food
	for rows.Next() {
		var f Food
		if err := rows.Scan(&f.ID, &f.Name, &f.ExpiryDate, &f.Quantity, &f.CategoryName); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, nil
}

func GetAllFoodsAdmin(userID int) ([]map[string]interface{}, error) {
	hasPerm, err := UserHasPermission(userID, "view_food")
	if err != nil || !hasPerm {
		return nil, fmt.Errorf("permission denied to view food")
	}

	rows, err := DB.Query("SELECT food_id, food_name, quantity, expiry_date, username, category_name FROM view_all_foods")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var foodID, quantity int
		var name, expiry, username, category string
		if err := rows.Scan(&foodID, &name, &quantity, &expiry, &username, &category); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"id":         foodID,
			"name":       name,
			"quantity":   quantity,
			"expiryDate": expiry,
			"user":       username,
			"category":   category,
		})
	}
	return result, nil
}

func GetAllRecipesAdmin(userID int) ([]map[string]interface{}, error) {
	hasPerm, err := UserHasPermission(userID, "view_recipes")
	if err != nil || !hasPerm {
		return nil, fmt.Errorf("permission denied to view recipes")
	}

	rows, err := DB.Query("SELECT recipe_id, recipe, created_at, created_by, ingredients FROM view_all_recipes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id int
		var recipe, createdAt, createdBy, ingredients string
		if err := rows.Scan(&id, &recipe, &createdAt, &createdBy, &ingredients); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"id":          id,
			"recipe":      recipe,
			"createdAt":   createdAt,
			"createdBy":   createdBy,
			"ingredients": strings.Split(ingredients, ","),
		})
	}
	return result, nil
}

func GetAllUserLogsAdmin(userID int) ([]map[string]interface{}, error) {
	hasPerm, err := UserHasPermission(userID, "view_login_logs")
	if err != nil || !hasPerm {
		return nil, fmt.Errorf("permission denied to view user logs")
	}

	rows, err := DB.Query("SELECT user_id, username, email, role_name, login_time, ip_address FROM view_all_user_logs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var uid int
		var username, email, role, loginTime, ip string
		if err := rows.Scan(&uid, &username, &email, &role, &loginTime, &ip); err != nil {
			return nil, err
		}
		logs = append(logs, map[string]interface{}{
			"user_id":    uid,
			"username":   username,
			"email":      email,
			"role":       role,
			"login_time": loginTime,
			"ip_address": ip,
		})
	}
	return logs, nil
}

func GetCategories() ([]map[string]interface{}, error) {
	rows, err := DB.Query("SELECT id, name FROM categories")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		categories = append(categories, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	return categories, nil
}

func AddFoodRecipe(foodIDs []int, recipe string, userID string) error {
	// Cek apakah userID valid
	uid, err := strconv.Atoi(userID)
	if err != nil {
		return err
	}

	// 1. Simpan resep ke food_recipes
	res, err := DB.Exec("INSERT INTO food_recipes (recipe, user_id) VALUES (?, ?)", recipe, uid)
	if err != nil {
		return err
	}

	// 2. Ambil ID resep terakhir yang dimasukkan
	recipeID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	// 3. Masukkan relasi ke tabel recipe_ingredients
	for _, foodID := range foodIDs {
		_, err := DB.Exec("INSERT INTO recipe_ingredients (recipe_id, food_id) VALUES (?, ?)", recipeID, foodID)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetFoodRecipes(userID string) ([]map[string]interface{}, error) {
	id, _ := strconv.Atoi(userID)
	rows, err := DB.Query("SELECT recipe_id, recipe, created_at, ingredients FROM view_all_recipes WHERE user_id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id int
		var recipe, createdAt, ingredients string
		if err := rows.Scan(&id, &recipe, &createdAt, &ingredients); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"id":          id,
			"recipe":      recipe,
			"createdAt":   createdAt,
			"ingredients": strings.Split(ingredients, ","),
		})
	}
	return result, nil
}

func GetLoginLogs(userID string) ([]map[string]interface{}, error) {
	id, _ := strconv.Atoi(userID)
	rows, err := DB.Query("SELECT login_time, ip_address FROM login_logs WHERE user_id = ? ORDER BY login_time DESC", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var loginTime, ip string
		if err := rows.Scan(&loginTime, &ip); err != nil {
			return nil, err
		}
		logs = append(logs, map[string]interface{}{
			"login_time": loginTime,
			"ip_address": ip,
		})
	}
	return logs, nil
}

func DeleteOldLoginLogs(userID string, keepLatest int) error {
	_, err := DB.Exec(`
		DELETE FROM login_logs 
		WHERE user_id = ? AND id NOT IN (
			SELECT id FROM (
				SELECT id FROM login_logs WHERE user_id = ? ORDER BY login_time DESC LIMIT ?
			) AS temp
		)`, userID, userID, keepLatest)
	return err
}

func RegisterHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Bad request"})
		return
	}
	if !isValidEmail(req.Email) || !isValidPassword(req.Password) {
		c.JSON(400, gin.H{"error": "Email or password format invalid"})
		return
	}
	var exists string
	if err := DB.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&exists); err == nil {
		c.JSON(409, gin.H{"error": "Username already exists"})
		return
	}
	hashed, _ := hashPassword(req.Password)
	var roleID int
	if err := DB.QueryRow("SELECT id FROM roles WHERE name = ?", req.Role).Scan(&roleID); err != nil {
		c.JSON(400, gin.H{"error": "Invalid role"})
		return
	}
	_, err := DB.Exec("INSERT INTO users (username, password, email, role_id) VALUES (?, ?, ?, ?)",
		req.Username, hashed, req.Email, roleID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to register"})
		return
	}
	c.JSON(200, gin.H{"message": "Registration successful"})
}

func LoginHandler(c *gin.Context) {
	fmt.Println("=== Login Process Started ===")
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Printf("Login error: Invalid request format - %v\n", err)
		c.JSON(400, gin.H{"error": "Bad request"})
		return
	}
	fmt.Printf("Login attempt for username: %s\n", req.Username)

	var userID int
	var hash, role string
	err := DB.QueryRow(`
		SELECT u.id, u.password, r.name
		FROM users u
		LEFT JOIN roles r ON u.role_id = r.id
		WHERE u.username = ?`, req.Username).Scan(&userID, &hash, &role)
	if err != nil {
		fmt.Printf("Login error: Database query failed - %v\n", err)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	fmt.Printf("User found in database. UserID: %d, Role: %s\n", userID, role)

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		fmt.Printf("Login error: Invalid password for user %s\n", req.Username)
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	fmt.Println("Password validation successful")

	token, err := GenerateJWT(req.Username)
	if err != nil {
		fmt.Printf("Login error: Failed to generate JWT - %v\n", err)
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}
	fmt.Println("JWT token generated successfully")

	// Log the login attempt
	clientIP := c.ClientIP()
	fmt.Printf("Client IP Address: %s\n", clientIP)
	fmt.Printf("Attempting to save login log for user %s (ID: %d) from IP %s\n", req.Username, userID, clientIP)

	if err := SaveLoginLog(fmt.Sprintf("%d", userID), req.Username, clientIP); err != nil {
		fmt.Printf("Warning: Failed to save login log - %v\n", err)
		// We continue despite log saving error
	} else {
		fmt.Printf("Login log saved successfully\n")
	}

	fmt.Println("=== Login Process Completed ===")
	c.JSON(200, gin.H{"token": token, "role": role})
}

func ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
		return
	}
	claims := token.Claims.(*Claims)
	var userID int
	var role string
	err = DB.QueryRow("SELECT u.id, r.name FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.username = ?", claims.Username).Scan(&userID, &role)
	if err != nil {
		c.AbortWithStatusJSON(401, gin.H{"error": "User not found"})
		return
	}
	c.Set("user_id", fmt.Sprintf("%d", userID))
	c.Set("username", claims.Username)
	c.Set("role", role)
	c.Next()
}

func DeleteUser(requesterID int, targetUserID int) error {
	var requesterRoleID int
	err := DB.QueryRow("SELECT role_id FROM users WHERE id = ?", requesterID).Scan(&requesterRoleID)
	if err != nil {
		return fmt.Errorf("user tidak ditemukan")
	}

	if requesterRoleID != 1 { // 1 adalah ID untuk super_admin
		return fmt.Errorf("hanya super admin yang dapat menghapus user")
	}

	if targetUserID == requesterID {
		return fmt.Errorf("super admin tidak dapat menghapus dirinya sendiri")
	}

	var targetRoleID int
	err = DB.QueryRow("SELECT role_id FROM users WHERE id = ?", targetUserID).Scan(&targetRoleID)
	if err != nil {
		return fmt.Errorf("user yang akan dihapus tidak ditemukan")
	}

	if targetRoleID == 1 {
		return fmt.Errorf("tidak dapat menghapus user super admin lainnya")
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM login_logs WHERE user_id = ?", targetUserID)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("DELETE FROM food_recipes WHERE user_id = ?", targetUserID)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("DELETE FROM foods WHERE user_id = ?", targetUserID)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("DELETE FROM users WHERE id = ?", targetUserID)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func GetUsers() ([]map[string]interface{}, error) {
	rows, err := DB.Query(`
		SELECT u.id, u.username, u.email, r.name AS role
		FROM users u
		LEFT JOIN roles r ON u.role_id = r.id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, email, role string
		if err := rows.Scan(&id, &username, &email, &role); err != nil {
			return nil, err
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"email":    email,
			"role":     role,
		})
	}
	return users, nil
}
