package router

import (
	"trivy_v3/controllers"
	"trivy_v3/models"

	"github.com/gin-gonic/gin"
)

func Router() {
	r := gin.Default()
	r.Use(CORS)
	models.ConnectDatabase()
	r.GET("/", controllers.HelloUser)
	// untuk API Project
	r.GET("/project", controllers.FindProjects)
	r.GET("/project/:id", controllers.FindProject)
	r.POST("/project", controllers.PostProject)
	r.PUT("/project/:id", controllers.UpdateProject)
	r.DELETE("/project/:id", controllers.DeleteProject)
	r.GET("/data/:id", controllers.GetProjects)

	// untuk API Upload
	r.GET("/upload", controllers.FindDockers)
	r.POST("/upload", controllers.PostDockerfile)
	r.GET("/upload/:id", controllers.FindDocker)
	r.PUT("/upload/:id", controllers.UpdateDocker)
	r.DELETE("/upload/:id", controllers.DeleteDocker)

	// untuk API Code
	r.GET("/code", controllers.FindCodes)
	r.POST("/code", controllers.PostCode)
	r.GET("/code/:id", controllers.FindCode)
	r.PUT("/code/:id", controllers.UpdateCode)
	r.DELETE("/code/:id", controllers.DeleteCode)

	// untuk API return JSON
	r.GET("/jsonfile/:id", controllers.GetJson)

	r.Run()
}

func CORS(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, "+
		"Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}
