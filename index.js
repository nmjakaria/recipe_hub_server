const dns = require("node:dns");
// 1. Fix DNS lookup issues globally in your Node app
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.SERVER_PORT || 5000;
const uri = process.env.MONGO_DB_URI;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

// ✅ UPDATED: Added user assignment and fixed response key typos
const verifyToken = async (req, res, next) => {
    const authHeader = req?.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Unauthorized: Missing token header" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Unauthorized: Malformed token string" });
    }

    try {
        const { payload } = await jwtVerify(token, JWKS);

        // 🌟 CRITICAL FIX: Save the validated payload claims to req.user for down-stream routes
        req.user = {
            id: payload.id || payload.sub, // Better Auth places the primary identifier in id/sub
            email: payload.email,
            role: payload.role || 'user'
        };

        next();
    } catch (error) {
        console.error("JWT verification failed:", error.message);
        return res.status(403).json({ message: "Forbidden: Token has expired or is invalid" });
    }
};

// Connect to MongoDB ONCE when the server starts
async function startServer() {
    try {
        await client.connect();

        const db = client.db("recipehub_db");
        const recipesCollection = db.collection("recipes");
        const recipeLikesCollection = db.collection("recipeLikes");

        // --- PUBLIC ROUTES ---

        app.get('/api/recipes', async (req, res) => {
            const query = {};
            if (req.query.authorId) {
                query.authorId = req.query.authorId;
            }
            if (req.query.status) {
                query.status = req.query.status;
            }
            const cursor = recipesCollection.find(query);
            const result = await cursor.toArray();
            res.send(result);
        });

        app.get('/api/recipes/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await recipesCollection.findOne(query);
            res.send(result);
        });

        // --- PROTECTED ROUTES (Using verifyToken middleware) ---

        // Anyone creating a recipe must have a valid account session
        app.post('/api/recipes', verifyToken, async (req, res) => {
            const recipe = req.body;

            // Optional improvement: Dynamically lock the creator's ID to the data payload
            recipe.authorId = req.user.id;

            try {
                const result = await recipesCollection.insertOne(recipe);
                res.status(201).json({ message: 'Recipe added successfully', id: result.insertedId });
            } catch (error) {
                console.error("Error adding recipe:", error);
                res.status(500).json({ message: 'Error adding recipe' });
            }
        });

        app.post('/api/recipes/:id/like', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;

                const userId = req.user.id;

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).send({ message: "Invalid Recipe ID format" });
                }

                const recipeObjectId = new ObjectId(recipeId);
                const existingLikeQuery = {
                    recipeId: recipeObjectId,
                    userId: userId
                };

                const hasLiked = await recipeLikesCollection.findOne(existingLikeQuery);

                if (hasLiked) {
                    // --- UNLIKE ACTION ---
                    await recipeLikesCollection.deleteOne(existingLikeQuery);

                    const updateResult = await recipesCollection.findOneAndUpdate(
                        { _id: recipeObjectId },
                        { $inc: { likesCount: -1 } },
                        { returnDocument: 'after' }
                    );

                    return res.send({
                        liked: false,
                        likesCount: updateResult?.likesCount || 0,
                        message: "Recipe unliked successfully"
                    });

                } else {
                    // --- LIKE ACTION ---
                    await recipeLikesCollection.insertOne({
                        recipeId: recipeObjectId,
                        userId: userId,
                        createdAt: new Date()
                    });

                    const updateResult = await recipesCollection.findOneAndUpdate(
                        { _id: recipeObjectId },
                        { $inc: { likesCount: 1 } },
                        { returnDocument: 'after' }
                    );

                    return res.send({
                        liked: true,
                        likesCount: updateResult?.likesCount || 1,
                        message: "Recipe liked successfully"
                    });
                }

            } catch (error) {
                console.error("Like system execution exception:", error);
                res.status(500).send({ message: "Internal server error tracking engagement states" });
            }
        });

        // Check database connectivity
        await client.db("admin").command({ ping: 1 });
        console.log("Connected to MongoDB successfully!");

        // Start listening only AFTER database connection succeeds
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });

    } catch (error) {
        console.error("Failed to connect to the database:", error);
        process.exit(1);
    }
}

// Global routes
app.get('/', (req, res) => {
    res.send('Recipe hub Server is running!');
});

startServer();