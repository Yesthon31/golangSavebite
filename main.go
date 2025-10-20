package main

import (
	"api/db"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type RecipeIngredient struct {
	ID       int `json:"id"`
	Quantity int `json:"quantity"`
	FoodID   int `json:"food_id"`
}

type RecipeRequest struct {
	Ingredients []RecipeIngredient `json:"ingredients"`
}

type FertilizerIngredient struct {
	ID       int `json:"id"`
	Quantity int `json:"quantity"`
	FoodID   int `json:"food_id"`
}

type FertilizerRequest struct {
	Ingredients []FertilizerIngredient `json:"ingredients"`
}

type ChatMessage struct {
	Message string `json:"message" binding:"required"`
}

type ChatResponse struct {
	Response string `json:"response"`
}

func chatHandler(c *gin.Context) {
	startTime := time.Now()
	log.Printf("Starting new chat request")

	var req ChatMessage
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	log.Printf("Received message: %s", req.Message)

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Printf("API key not found in environment variables")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "API key not configured"})
		return
	}
	log.Printf("Using API Key: %s", apiKey[:10]+"...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("Creating Gemini client...")
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		log.Printf("DETAILED ERROR - Creating client: %+v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to initialize AI client: %v", err)})
		return
	}
	defer client.Close()
	log.Printf("Gemini client created successfully")

	model := client.GenerativeModel("gemini-2.5-flash")
	model.SetTemperature(0.7)

	prompt := fmt.Sprintf(`The user asks: %s
	Answer in English with a neat and easy-to-read layout suitable for the application.
	Provide your response in the following format:
	1. If the question is about food, always include:
	   - Shelf life at room temperature: (specify how many hours/days)
	   - Shelf life in the refrigerator: (specify how many days)
	   - Storage tips: (give short, practical tips)
	
	2. If the question is about something else:
	   - Politely explain that the question should be about food
	   - Do not provide irrelevant information
	
	Use formal and friendly English. Avoid using symbols such as * or #.
	You are an AI assistant from SaveBite, a company focused on food safety.`, req.Message)

	log.Printf("Sending prompt to Gemini with message length: %d", len(req.Message))

	var resp *genai.GenerateContentResponse
	maxRetries := 3
	var lastError error

	for i := 0; i < maxRetries; i++ {
		resp, err = model.GenerateContent(ctx, genai.Text(prompt))
		if err == nil {
			break
		}
		lastError = err
		log.Printf("DETAILED ERROR - Attempt %d failed with error type %T: %+v", i+1, err, err)
		if i < maxRetries-1 {
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	if lastError != nil {
		log.Printf("FINAL ERROR after %d attempts: %+v", maxRetries, lastError)
		errorMsg := fmt.Sprintf("Failed to generate response: %v", lastError)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
		return
	}

	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		log.Printf("No response candidates received from Gemini")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No response generated"})
		return
	}

	var response strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		response.WriteString(fmt.Sprintf("%v", part))
	}

	duration := time.Since(startTime)
	responseLength := response.Len()
	log.Printf("Successfully generated response in %v. Response length: %d characters", duration, responseLength)
	c.JSON(http.StatusOK, ChatResponse{
		Response: response.String(),
	})
}

func main() {
	db.InitDB()
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization", "X-CSRF-Token"},
	}))

	r.OPTIONS("/*path", func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNoContent)
	})

	r.POST("/register", db.RegisterHandler)
	r.POST("/login", db.LoginHandler)
	r.POST("/chat", chatHandler)

	auth := r.Group("/")
	auth.Use(db.ValidateToken)

	auth.GET("/foods", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		data, err := db.GetFoods(userID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal mengambil makanan"})
			return
		}
		c.JSON(200, data)
	})

	auth.GET("/categories", func(c *gin.Context) {
		categories, err := db.GetCategories()
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal mengambil kategori"})
			return
		}
		c.JSON(200, categories)
	})

	auth.DELETE("/users/:id", func(c *gin.Context) {
		currentUserID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		targetUserID, err := strconv.Atoi(c.Param("id"))

		if err != nil {
			c.JSON(400, gin.H{"error": "ID user tidak valid"})
			return
		}

		err = db.DeleteUser(currentUserID, targetUserID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "User berhasil dihapus"})
	})

	auth.GET("/check-permission", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		permission := c.Query("permission")

		if permission == "" {
			c.JSON(400, gin.H{"error": "Permission parameter is required"})
			return
		}

		hasPerm, err := db.UserHasPermission(userID, permission)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to check permission"})
			return
		}

		c.JSON(200, gin.H{"has_permission": hasPerm})
	})

	auth.POST("/foods", func(c *gin.Context) {
		var req db.AddFoodRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Format salah"})
			return
		}
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		err := db.AddFood(req.Name, req.ExpiryDate, req.Quantity, userID, req.CategoryID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "Makanan disimpan"})
	})

	auth.GET("/recipes", func(c *gin.Context) {
		userID := c.MustGet("user_id").(string)
		data, err := db.GetFoodRecipes(userID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal mengambil resep"})
			return
		}
		c.JSON(200, data)
	})

	auth.GET("/fertilizers", func(c *gin.Context) {
		userID := c.MustGet("user_id").(string)
		data, err := db.GetFoodFertilizers(userID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal mengambil pupuk"})
			return
		}
		c.JSON(200, data)
	})

	auth.POST("/recipe", func(c *gin.Context) {
		var req RecipeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Format salah"})
			return
		}
		userID := c.MustGet("user_id").(string)

		var foodNames []string
		var foodIDs []int
		for _, item := range req.Ingredients {
			var name string
			var stock int
			err := db.DB.QueryRow("SELECT name, quantity FROM foods WHERE id = ? AND user_id = ?", item.ID, userID).Scan(&name, &stock)
			if err != nil {
				c.JSON(404, gin.H{"error": fmt.Sprintf("Makanan ID %d tidak ditemukan", item.ID)})
				return
			}
			if stock < item.Quantity {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Stok tidak cukup untuk %s", name)})
				return
			}
			foodNames = append(foodNames, fmt.Sprintf("%dx %s", item.Quantity, name))
			foodIDs = append(foodIDs, item.ID)
		}

		apiKey := os.Getenv("API_KEY")
		ctx := context.Background()
		client, _ := genai.NewClient(ctx, option.WithAPIKey(apiKey))
		defer client.Close()

		model := client.GenerativeModel("gemini-2.5-flash")
		prompt := fmt.Sprintf(
			"Create a delicious recipe using the following ingredients: %s.\n\n"+
				"Start with the recipe title first, then write in an engaging and easy-to-read style suitable for the app. "+
				"Make sure each step is neatly formatted, spaced properly, and all step numbers are aligned. "+
				"No need for introductory phrases—go straight to the recipe title:\n\n"+
				"🍽️ Recipe Title\n"+
				"📝 A short description of the dish\n"+
				"🥦 Ingredients:\n"+
				"- Use emojis that match the ingredients (for example: 🍅, 🧄, 🧂, 🍚)\n\n"+
				"👨‍🍳 Cooking Steps:\n"+
				"- Write each step clearly and concisely\n"+
				"- Add emojis to highlight important actions (for example: 🔥 when cooking, 🍽️ when serving)\n\n"+
				"💡 Add extra tips if available\n\n"+
				"End with the sentence: '👨‍🍳 by Chef SaveBite'",
			strings.Join(foodNames, ", "),
		)

		resp, _ := model.GenerateContent(ctx, genai.Text(prompt))

		var out strings.Builder
		for _, part := range resp.Candidates[0].Content.Parts {
			out.WriteString(fmt.Sprintf("%v\n", part))
		}

		db.AddFoodRecipe(foodIDs, out.String(), userID)
		c.JSON(200, db.RecipeResponse{Recipe: out.String()})
	})

	auth.POST("/fertilizer", func(c *gin.Context) {
		var req FertilizerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Format salah"})
			return
		}
		userID := c.MustGet("user_id").(string)

		var foodNames []string
		var foodIDs []int
		for _, item := range req.Ingredients {
			var name string
			var stock int
			err := db.DB.QueryRow("SELECT name, quantity FROM foods WHERE id = ? AND user_id = ?", item.ID, userID).Scan(&name, &stock)
			if err != nil {
				c.JSON(404, gin.H{"error": fmt.Sprintf("Makanan ID %d tidak ditemukan", item.ID)})
				return
			}
			if stock < item.Quantity {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Stok tidak cukup untuk %s", name)})
				return
			}
			foodNames = append(foodNames, fmt.Sprintf("%dx %s", item.Quantity, name))
			foodIDs = append(foodIDs, item.ID)
		}

		apiKey := os.Getenv("API_KEY")
		ctx := context.Background()
		client, _ := genai.NewClient(ctx, option.WithAPIKey(apiKey))
		defer client.Close()

		model := client.GenerativeModel("gemini-2.5-flash")
		prompt := fmt.Sprintf(
			"Create a guide for making organic fertilizer using the following ingredients: %s.\n\n"+
				"Start directly with the fertilizer title. Write it in an engaging and easy-to-read style suitable for the application. Each step should be neatly formatted, well-spaced, and the numbering aligned.\n\n"+
				"🌱 Fertilizer Title\n"+
				"📝 A short description of the fertilizer and its benefits\n"+
				"🥬 Ingredients:\n"+
				"- Use emojis that match the ingredients (e.g., 🍌, 🥕, 🥬, 🍃)\n\n"+
				"🔧 Preparation Steps:\n"+
				"- Write clear and concise steps\n"+
				"- Add emojis for key actions (e.g., ✂️ for cutting, 🥄 for mixing, ⏰ for fermentation)\n\n"+
				"💡 Tips for usage and storage\n\n"+
				"End with the sentence: '🌱 by SaveBite Eco Solutions'",
			strings.Join(foodNames, ", "),
		)

		resp, _ := model.GenerateContent(ctx, genai.Text(prompt))

		var out strings.Builder
		for _, part := range resp.Candidates[0].Content.Parts {
			out.WriteString(fmt.Sprintf("%v\n", part))
		}

		db.AddFoodFertilizer(foodIDs, out.String(), userID)
		c.JSON(200, db.FertilizerResponse{Fertilizer: out.String()})
	})

	auth.DELETE("/recipes/:id", func(c *gin.Context) {
		id := c.Param("id")
		userID := c.MustGet("user_id").(string)
		var recipeUser string
		err := db.DB.QueryRow("SELECT user_id FROM food_recipes WHERE id = ?", id).Scan(&recipeUser)
		if err != nil || recipeUser != userID {
			c.JSON(403, gin.H{"error": "Resep bukan milik Anda"})
			return
		}
		db.DB.Exec("DELETE FROM food_recipes WHERE id = ?", id)
		c.JSON(200, gin.H{"message": "Resep dihapus"})
	})

	auth.DELETE("/fertilizers/:id", func(c *gin.Context) {
		id := c.Param("id")
		userID := c.MustGet("user_id").(string)
		var fertilizerUser string
		err := db.DB.QueryRow("SELECT user_id FROM food_fertilizers WHERE id = ?", id).Scan(&fertilizerUser)
		if err != nil || fertilizerUser != userID {
			c.JSON(403, gin.H{"error": "Pupuk bukan milik Anda"})
			return
		}
		db.DB.Exec("DELETE FROM food_fertilizers WHERE id = ?", id)
		c.JSON(200, gin.H{"message": "Pupuk dihapus"})
	})

	auth.GET("/admin/foods", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		data, err := db.GetAllFoodsAdmin(userID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, data)
	})

	auth.GET("/admin/recipes", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		data, err := db.GetAllRecipesAdmin(userID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, data)
	})

	auth.GET("/admin/fertilizers", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		data, err := db.GetAllFertilizersAdmin(userID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, data)
	})

	auth.GET("/admin/logs", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		logs, err := db.GetAllUserLogsAdmin(userID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, logs)
	})

	auth.DELETE("/foods/:id", func(c *gin.Context) {
		id := c.Param("id")
		userID := c.MustGet("user_id").(string)
		err := db.DeleteFood(id, userID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "Makanan dihapus"})
	})

	auth.GET("/login-logs", func(c *gin.Context) {
		userID := c.MustGet("user_id").(string)
		logs, err := db.GetLoginLogs(userID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal ambil log"})
			return
		}
		if len(logs) > 100 {
			db.DeleteOldLoginLogs(userID, 100)
		}
		c.JSON(200, gin.H{"login_logs": logs})
	})

	auth.GET("/users", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		hasPerm, err := db.UserHasPermission(userID, "view_users")
		if err != nil || !hasPerm {
			c.JSON(403, gin.H{"error": "Tidak punya izin melihat user"})
			return
		}
		users, err := db.GetUsers()
		if err != nil {
			c.JSON(500, gin.H{"error": "Gagal ambil user"})
			return
		}
		c.JSON(200, gin.H{"users": users})
	})

	auth.DELETE("/admin/category/:id", func(c *gin.Context) {
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		catID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(400, gin.H{"error": "ID tidak valid"})
			return
		}
		err = db.DeleteCategory(userID, catID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "Kategori berhasil dihapus"})
	})
	auth.POST("/admin/category", func(c *gin.Context) {
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Format salah"})
			return
		}
		userID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		err := db.AddCategory(userID, req.Name)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "Kategori ditambahkan"})
	})

	auth.POST("/admin/promote", func(c *gin.Context) {
		var req struct {
			TargetUserID int    `json:"target_user_id"`
			NewRoleName  string `json:"new_role_name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Format salah"})
			return
		}
		requesterID, _ := strconv.Atoi(c.MustGet("user_id").(string))

		hasPerm, err := db.UserHasPermission(requesterID, "promote_user_to_role")
		if err != nil || !hasPerm {
			c.JSON(403, gin.H{"error": "Tidak punya izin promosi role"})
			return
		}

		err = db.PromoteUserToRole(requesterID, req.TargetUserID, req.NewRoleName)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "User berhasil dipromosikan"})
	})

	auth.DELETE("/admin/users/:id", func(c *gin.Context) {
		requesterID, _ := strconv.Atoi(c.MustGet("user_id").(string))
		targetUserID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(400, gin.H{"error": "ID user tidak valid"})
			return
		}

		if targetUserID == requesterID {
			c.JSON(400, gin.H{"error": "Tidak dapat menghapus diri sendiri"})
			return
		}

		err = db.DeleteUser(requesterID, targetUserID)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "User berhasil dihapus"})
	})

	r.Run(":8080")

}
