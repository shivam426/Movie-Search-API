package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Println("Starting the application...")
	ctx, Cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer Cancel()
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, _ = mongo.Connect(ctx, clientOptions)
	router := mux.NewRouter()
	router.HandleFunc("/movies", CreateMoviesEndpoint).Methods("POST")
	router.HandleFunc("/title", GetTitleEndpoint).Methods("GET")
	router.HandleFunc("/movies/{id}", GetMoviesEndpoint).Methods("GET")
	router.HandleFunc("/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/login", LoginHandler).Methods("POST")
	router.HandleFunc("/profile", ProfileHandler).Methods("GET")
	router.HandleFunc("/movies/{id}", DeleteMovieEndPoint).Methods("DELETE")
	router.HandleFunc("/movies/{id}", UpdateMovieEndPoint).Methods("PUT")
	router.HandleFunc("/movies", SearchEndPoint).Methods("GET")
	http.ListenAndServe(":12345", router)

}

// User is for users
type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name     string             `json:"name,omitempty" bson:"name,omitempty"`
	Email    string             `json:"email,omitempty" bson:"email,omitempty"`
	Username string             `json:"username,omitempty" bson:"username,omitempty"`
	Password string             `json:"password,omitempty" bson:"password,omitempty"`
}

// ResponseResult is fetching result
type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}

var client *mongo.Client

var SECRETKEY = []byte("aws12")

//Movies is for all movies
type Movies struct {
	ID         primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name       string             `json:"name,omitempty" bson:"name,omitempty"`
	ImdbScore  float64            `json:"imdbscore,omitempty" bson:"imdbscore,omitempty"`
	Popularity float64            `json:"popularity,omitempty" bson:"popularity,omitempty"`
	Director   string             `json:"director,omitempty" bson:"director,omitempty"`
	Genre      []string           `json:"genre,omitempty" bson:"genre,omitempty"`
}
type ErrorResponse struct {
	Code    int
	Message string
}
type Claims struct {
	Email string
	// Password string
	jwt.StandardClaims
}





func returnErrorResponse(response http.ResponseWriter, request *http.Request, errorMesage ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMesage.Code, Message: errorMesage.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(errorMesage.Code)
	response.Write(jsonResponse)
}

//CreateMoviesEndpoint is to create movies
func CreateMoviesEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	var movies []interface{}
	err := json.NewDecoder(request.Body).Decode(&movies)
	fmt.Println("doc: ", movies, err)
	collection := client.Database("movies").Collection("imdb")
	ctx, Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer Cancel()
	result, _ := collection.InsertMany(ctx, movies)
	json.NewEncoder(response).Encode(result)
}

//GetMoviesEndpoint is fetch single data
func GetMoviesEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var movies Movies
	collection := client.Database("movies").Collection("imdb")
	ctx, Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer Cancel()
	err := collection.FindOne(ctx, Movies{ID: id}).Decode(&movies)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(movies)
}

// GetTitleEndpoint is fetch data
func GetTitleEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("content-type", "application/json")
	var title []Movies
	collection := client.Database("movies").Collection("imdb")
	ctx, Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer Cancel()
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var movies Movies
		cursor.Decode(&movies)
		title = append(title, movies)
	}
	if err := cursor.Err(); err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(title)
}

//DeleteMovieEndPoint an existing movie
func DeleteMovieEndPoint(response http.ResponseWriter, request *http.Request){
	response.Header().Set("Content-Type", "application/")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var movie Movies
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Authentication Token Mismatched",
	}
	bearerToken := request.Header.Get("cookie")
	var authorizationToken string
	authorizationTokenArray := strings.Split(bearerToken, "=")
	if len(authorizationTokenArray) > 1 {
		authorizationToken = authorizationTokenArray[1]
	}
	email, _ := VerifyToken(authorizationToken)
	if email == "" {
		returnErrorResponse(response, request, errorResponse)
	} else {
		collection := client.Database("imdb").Collection("movie")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := collection.FindOneAndDelete(ctx, Movies{ID: id}).Decode(&movie)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{ "message": "` + err.Error() + `" }`))

		} else {
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusOK)
			res := make(map[string]interface{})
			res["deletedID"] = id
			res["response"] = "Deleted Successfully"
			des, _ := json.Marshal(res)
			response.Write([]byte(des))
		}
	}

}


//UpdateMovieEndPoint an existing movie"
func UpdateMovieEndPoint(response http.ResponseWriter, request *http.Request)  {
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var movie Movies
	_ = json.NewDecoder(request.Body).Decode(&movie)
	collection := client.Database("imdb").Collection("movie")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := Movies{ID: id}
	update := bson.M{"$set": movie}
	// upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		// Upsert:         &upsert,
	}
	resp := bson.M{}
	result := collection.FindOneAndUpdate(ctx, filter, update, &opt).Decode(&resp)

	if result != nil {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusNotFound)
		res := make(map[string]interface{})
		// res["updated_data"] = resp
		res["response"] = "Data Not Found"
		des, _ := json.Marshal(res)
		response.Write([]byte(des))
	} else {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		res := make(map[string]interface{})
		res["updated_data"] = resp
		res["response"] = "Updated Successfully"
		des, _ := json.Marshal(res)
		response.Write([]byte(des))
	}
}

// RegisterHandler is to register
func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	var user User
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &user)
	var res ResponseResult
	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	collection := client.Database("gologin").Collection("user")
	ctx, Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer Cancel()
	// result, _ := collection.InsertMany(ctx, movies)

	if err != nil {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}
	result := User{}
	// var User
	err = collection.FindOne(ctx, bson.D{{"username", user.Username}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

			if err != nil {
				res.Error = "Error While Hashing Password, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			user.Password = string(hash)

			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Error = "Error While Creating User, Try Again"
				json.NewEncoder(w).Encode(res)
				return
			}
			res.Result = "Registration Successful"
			json.NewEncoder(w).Encode(res)
			return
		}

		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Result = "Username already Exists!!"
	json.NewEncoder(w).Encode(res)
	return
}


func GenerateJWT(email string) (string, error) {
	// expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		// Password: password,
		StandardClaims: jwt.StandardClaims{

			// ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(SECRETKEY)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}

// VerifyToken is function for Token verification
func VerifyToken(tokenString string) (email string, err error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return SECRETKEY, nil
	})
	if token != nil {
		return claims.Email, nil
	}
	return "", err
}

// LoginHandler is for login
func LoginHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbUser User
	_ = json.NewDecoder(request.Body).Decode(&user)
	fmt.Println(user)
	collection := client.Database("users").Collection("register")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte(`{"message":"` + err.Error() + `"}`))
		return
	}
	userPass := []byte(user.Password)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		response.WriteHeader(http.StatusUnauthorized)
		response.Header().Set("Content-Type", "application/json")
		response.Write([]byte(`{"response":"Wrong Password!"}`))
	} else {
		jwtToken, err := GenerateJWT(user.Email)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Header().Set("Content-Type", "application/json")
			response.Write([]byte(`{"message":"` + err.Error() + `"}`))
			return
		}
		addCookie(response, "Bearer", jwtToken)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	res := make(map[string]interface{})
	res["response"] = "Login Successfully"
	des, _ := json.Marshal(res)
	response.Write([]byte(des))

}


//ProfileHandler is for profile
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	})
	var result User
	var res ResponseResult
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// result.Username = claims["username"].(string)
		// result.FirstName = claims["firstname"].(string)
		// result.LastName = claims["lastname"].(string)
      
		json.NewEncoder(w).Encode(result)
		return
	} else {
		res.Error = err.Error()
		json.NewEncoder(w).Encode(res)
		return
	}

}


func addCookie(w http.ResponseWriter, name, value string) {
	// expire := time.Now().Add(ttl)
	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		// Expires: expire,
	}
	http.SetCookie(w, &cookie)
}

// SearchEndPoint searching a movies
func SearchEndPoint(w http.ResponseWriter, req *http.Request) {
	content := req.Header.Get("content-type")
	var getmovie []Movies
	name := req.URL.Query().Get("name")
	genre := req.URL.Query().Get("genre")
	popularity := req.URL.Query().Get("popularity")
	director := req.URL.Query().Get("director")
	imdbscore := req.URL.Query().Get("imdb")
	fmt.Println("name: ", name)
	collection := client.Database("movies").Collection("imdb")
	ctx, Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer Cancel()

	filter := bson.M{}
	if name != "" {
		filter["name"] =
			bson.M{
				"$regex":   name,
				"$options": "i",
			}
	}
	if genre != "" {
		filter["genre"] =
			bson.M{
				"$regex":   genre,
				"$options": "i",
			}
	}
	n, _ := strconv.ParseInt(popularity, 10, 64)
	if popularity != "" {
		filter["popularity"] = bson.M{
			"$gt": n,
		}
	}
	if director != "" {
		filter["director"] =
			bson.M{
				"$regex":   director,
				"$options": "i",
			}
	}
	imdb, _ := strconv.ParseFloat(imdbscore, 32)
	if imdbscore != "" {
		filter["imdbscore"] =
			bson.M{
				"$gt": imdb,
			}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var movies Movies
		cursor.Decode(&movies)
		getmovie = append(getmovie, movies)
	}

	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	if content == "application/json" {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		res := make(map[string]interface{})
		res["Search_data"] = getmovie
		des, _ := json.Marshal(res)
		w.Write([]byte(des))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.ParseFiles("template.html")
	if err != nil {
		fmt.Fprintf(w, "Unable to load template")
	}

	t.Execute(w, getmovie)
}

// CreateIndex creation of index
func CreateIndex(imdb string, name string, imdbscore float64, popularity float64, director string, genre []string, id primitive.ObjectID, unique bool) bool {

	// 1. Lets define the keys for the index we want to create
	mod := mongo.IndexModel{
		Keys:    bson.M{"name": 1, "imdbscore": 1, "popularity": 1, "director": 1, "genre": 1, "id": 1}, // index in ascending order or -1 for descending order
		Options: options.Index().SetUnique(unique),
	}

	// 2. Create the context for this operation
	collection := client.Database("movies").Collection("imdb")
	ctx, Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer Cancel()

	// 4. Create a single index
	_, err := collection.Indexes().CreateOne(ctx, mod)
	if err != nil {
		// 5. Something went wrong, we log it and return false
		fmt.Println(err.Error())
		return false
	}

	// 6. All went well, we return true
	return true
}