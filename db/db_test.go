package db

import (
	"database/sql"
	"log"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func init() {
	var err error
	DB, err = sql.Open("mysql", "root@tcp(127.0.0.1:3306)/ceksavebite_test")
	if err != nil {
		log.Fatalf("Gagal konek DB: %v", err)
	}
	if err := DB.Ping(); err != nil {
		log.Fatalf("Ping DB gagal: %v", err)
	}
	log.Println("✅ Connected ke DB test")
}

func TestIsValidEmail(t *testing.T) {
	if !isValidEmail("test@example.com") {
		t.Error("Expected valid email")
	}
	if isValidEmail("invalid-email") {
		t.Error("Expected invalid email")
	}
}

func TestIsValidPassword(t *testing.T) {
	if !isValidPassword("Password@1") {
		t.Error("Expected valid password")
	}
	if isValidPassword("pass") {
		t.Error("Expected invalid password")
	}
}

func TestHashPassword(t *testing.T) {
	hashed, err := hashPassword("Password@123")
	if err != nil || hashed == "" {
		t.Error("Failed to hash password")
	}
}

func TestGenerateJWT(t *testing.T) {
	token, err := GenerateJWT("testuser")
	if err != nil || token == "" {
		t.Error("Failed to generate JWT")
	}
}

func TestAddCategory(t *testing.T) {
	err := AddCategory(1, "Unit Test Category")
	if err != nil {
		t.Errorf("Failed to add category: %v", err)
	}
}

func TestAddFood(t *testing.T) {
	err := AddFood("Unit Test Food", "2025-12-31", 5, 1, 1)
	if err != nil {
		t.Errorf("Failed to add food: %v", err)
	}
}

func TestUserHasPermission(t *testing.T) {
	hasPerm, err := UserHasPermission(1, "add_category")
	if err != nil {
		t.Errorf("Error checking permission: %v", err)
	}
	t.Logf("Permission result: %v", hasPerm)
}

func TestSaveLoginLog(t *testing.T) {
	err := SaveLoginLog("1", "testuser", "127.0.0.1")
	if err != nil {
		t.Errorf("Failed to save login log: %v", err)
	}
}

func TestGetFoods(t *testing.T) {
	foods, err := GetFoods(1)
	if err != nil {
		t.Errorf("Failed to get foods: %v", err)
	}
	t.Logf("Foods: %+v", foods)
}

func TestAddRecipe(t *testing.T) {
	err := AddRecipe("Test Recipe", []int{1}, 1)
	if err != nil {
		t.Errorf("Failed to add recipe: %v", err)
	}
}

func TestPromoteUserToRole(t *testing.T) {
	err := PromoteUserToRole(1, 2, "admin")
	if err != nil {
		t.Errorf("Failed to promote user: %v", err)
	}
}

func TestGetAllFoodsAdmin(t *testing.T) {
	foods, err := GetAllFoodsAdmin(1)
	if err != nil {
		t.Errorf("Failed to get admin foods: %v", err)
	}
	t.Logf("Admin Foods: %+v", foods)
}

func TestGetAllRecipesAdmin(t *testing.T) {
	recipes, err := GetAllRecipesAdmin(1)
	if err != nil {
		t.Errorf("Failed to get admin recipes: %v", err)
	}
	t.Logf("Admin Recipes: %+v", recipes)
}

func TestGetAllUserLogsAdmin(t *testing.T) {
	logs, err := GetAllUserLogsAdmin(1)
	if err != nil {
		t.Errorf("Failed to get admin logs: %v", err)
	}
	t.Logf("Admin Logs: %+v", logs)
}

func TestGetCategories(t *testing.T) {
	categories, err := GetCategories()
	if err != nil {
		t.Errorf("Failed to get categories: %v", err)
	}
	t.Logf("Categories: %+v", categories)
}

func TestGetFoodRecipes(t *testing.T) {
	recipes, err := GetFoodRecipes("1")
	if err != nil {
		t.Errorf("Failed to get food recipes: %v", err)
	}
	t.Logf("Food Recipes: %+v", recipes)
}

func TestGetLoginLogs(t *testing.T) {
	logs, err := GetLoginLogs("1")
	if err != nil {
		t.Errorf("Failed to get login logs: %v", err)
	}
	t.Logf("Login Logs: %+v", logs)
}

func TestDeleteOldLoginLogs(t *testing.T) {
	err := DeleteOldLoginLogs("1", 10)
	if err != nil {
		t.Errorf("Failed to delete old login logs: %v", err)
	}
}

func TestGetUsers(t *testing.T) {
	users, err := GetUsers()
	if err != nil {
		t.Errorf("Failed to get users: %v", err)
	}
	t.Logf("Users: %+v", users)
}
