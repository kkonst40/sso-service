package app

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kkonst40/isso/internal/config"
	pb "github.com/kkonst40/isso/internal/gen/user"
	"github.com/kkonst40/isso/internal/handler"
	"github.com/kkonst40/isso/internal/middleware"
	"github.com/kkonst40/isso/internal/repo"
	"github.com/kkonst40/isso/internal/service"
	"github.com/kkonst40/isso/internal/utils"
	"github.com/kkonst40/isso/internal/utils/auth"
	"google.golang.org/grpc"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type App struct {
	httpServer *http.Server
	grpcServer *grpc.Server
	grpcPort   string
	db         *sql.DB
}

func New(cfg *config.Config) (*App, error) {
	db, err := SetupDB(cfg.DB.User, cfg.DB.Password, cfg.DB.Host, cfg.DB.DBName)
	if err != nil {
		return nil, err
	}

	var (
		jwtProvider   = auth.NewJWTProvider(cfg)
		pwdHasher     = utils.NewPasswordHandler()
		credValidator = utils.NewValidator(cfg)
	)

	var (
		userRepo    = repo.New(db)
		userService = service.New(jwtProvider, pwdHasher, credValidator, userRepo, uuid.UUID{})
		userHandler = handler.New(userService, cfg)
	)

	apiRouter := http.NewServeMux()
	pagesRouter := http.NewServeMux()

	noAuthStack := middleware.CreateStack(
		middleware.Recovery,
		middleware.Timeout(3*time.Second),
	)

	authStack := middleware.CreateStack(
		middleware.Recovery,
		middleware.Timeout(3*time.Second),
		middleware.Auth(jwtProvider),
	)

	// for test
	pagesRouter.HandleFunc("GET /register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/register.html")
	})
	pagesRouter.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/login.html")
	})
	pagesRouter.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/me.html")
	})

	apiRouter.Handle("POST /login", noAuthStack(http.HandlerFunc(userHandler.Login)))
	apiRouter.Handle("POST /register", noAuthStack(http.HandlerFunc(userHandler.Create)))

	apiRouter.Handle("GET /me", authStack(http.HandlerFunc(userHandler.Me)))
	apiRouter.Handle("POST /logout", authStack(http.HandlerFunc(userHandler.Logout)))
	apiRouter.Handle("PUT /updatelogin", authStack(http.HandlerFunc(userHandler.UpdateLogin)))
	apiRouter.Handle("PUT /updatepassword", authStack(http.HandlerFunc(userHandler.UpdatePassword)))
	apiRouter.Handle("DELETE /{id}", authStack(http.HandlerFunc(userHandler.Delete)))

	router := http.NewServeMux()
	router.Handle("/api/", http.StripPrefix("/api", apiRouter))
	router.Handle("/", noAuthStack(pagesRouter))

	httpServer := &http.Server{
		Addr:    ":" + cfg.RestPort,
		Handler: router,
	}

	grpcServer := grpc.NewServer()
	userGRPC := handler.NewUserGRPCHandler(userService)
	pb.RegisterUserServiceServer(grpcServer, userGRPC)

	return &App{
		httpServer: httpServer,
		grpcServer: grpcServer,
		grpcPort:   cfg.GrpcPort,
		db:         db,
	}, nil
}

func (a *App) Run() error {
	errChan := make(chan error, 2)

	go func() {
		if err := a.httpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("HTTP serve error: %w", err)
		}
	}()

	go func() {
		grpcListener, err := net.Listen("tcp", ":"+a.grpcPort)
		if err != nil {
			errChan <- fmt.Errorf("gRPC listener error: %w", err)
			return
		}

		if err := a.grpcServer.Serve(grpcListener); err != nil {
			errChan <- fmt.Errorf("gRPC serve error: %w", err)
		}
	}()

	return <-errChan
}

func (a *App) Shutdown(ctx context.Context) {
	a.grpcServer.GracefulStop()

	if err := a.httpServer.Shutdown(ctx); err != nil {
		log.Println("Server forced to shutdown", "error", err.Error())
	}

	if err := a.db.Close(); err != nil {
		log.Println("DB close error", "error", err.Error())
	}
}

func SetupDB(user, pwd, host, dbName string) (*sql.DB, error) {
	dbUrl := fmt.Sprintf("postgres://%s:%s@%s/%s", user, pwd, host, dbName)

	db, err := sql.Open("pgx", dbUrl)
	if err != nil {
		return nil, fmt.Errorf("Error creating db object: %v", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("Failed to connect to the database: %v", err)
	}

	return db, nil
}
