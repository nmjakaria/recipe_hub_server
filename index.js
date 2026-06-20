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

const optionalVerifyToken = async (req, res, next) => {
    const authHeader = req?.headers.authorization;

    // If there's no token, we don't throw an error. We just treat them as a guest and move on.
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next();
    }

    const token = authHeader.split(" ")[1];
    try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = {
            id: payload.id || payload.sub,
            email: payload.email,
            role: payload.role || 'user'
        };
    } catch (error) {
        // If token is expired or invalid, log it but don't block the request
        console.log("Optional auth token invalid/expired, reading as guest");
    }

    next();
};

// Middleware to restrict routes to specific roles
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        // 1. Ensure the user is authenticated first
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized: Missing authentication context" });
        }

        // 2. Check if the user's role is permitted
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: `Forbidden: Access denied for role '${req.user.role}'` });
        }

        next();
    };
};

// Connect to MongoDB ONCE when the server starts
async function startServer() {
    try {
        await client.connect();

        const db = client.db("recipehub_db");
        const recipesCollection = db.collection("recipes");
        const recipeLikesCollection = db.collection("recipeLikes");
        const favoritesCollection = db.collection("recipeFavorites");
        const reportsCollection = db.collection("reports");

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

        // ✅ Clean and Hybrid: Accessible by everyone, but tracks state for logged-in accounts
        app.get('/api/recipes/:id', optionalVerifyToken, async (req, res) => {
            try {
                const id = req.params.id;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid Recipe ID format" });
                }

                const recipeObjectId = new ObjectId(id);
                const recipe = await recipesCollection.findOne({ _id: recipeObjectId });

                if (!recipe) {
                    return res.status(404).send({ message: "Recipe not found" });
                }

                let isLikedByUser = false;
                let isFavoritedByUser = false;

                // 🌟 If optionalVerifyToken found a user, check their engagement records
                if (req.user) {
                    const userId = req.user.id;

                    const likedRecord = await recipeLikesCollection.findOne({ recipeId: recipeObjectId, userId });
                    const favoritedRecord = await favoritesCollection.findOne({ recipeId: recipeObjectId, userId });

                    if (likedRecord) isLikedByUser = true;
                    if (favoritedRecord) isFavoritedByUser = true;
                }

                // Return combined data matrix
                res.send({ ...recipe, isLikedByUser, isFavoritedByUser });
            } catch (error) {
                console.error("Error fetching recipe:", error);
                res.status(500).send({ message: "Internal server error fetching recipe details" });
            }
        });

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

        // ==========================================
        // 2. TOGGLE FAVORITE API ROUTE
        // ==========================================
        app.post('/api/recipes/:id/favorite', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;
                const userId = req.user.id;
                const userEmail = req.user.email;
                const { recipeName } = req.body; // Sent from frontend data context

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ message: "Invalid Recipe ID format" });
                }

                const recipeObjectId = new ObjectId(recipeId);
                const favoriteQuery = { recipeId: recipeObjectId, userId: userId };

                const existingFavorite = await favoritesCollection.findOne(favoriteQuery);

                if (existingFavorite) {
                    // Remove from favorites if it exists
                    await favoritesCollection.deleteOne(favoriteQuery);
                    return res.json({ favorited: false, message: "Removed from favorites collection" });
                } else {
                    // Add to favorites if it doesn't exist
                    const newFavoriteDoc = {
                        userId,
                        userEmail,
                        recipeId: recipeObjectId,
                        recipeName: recipeName || "Unnamed Recipe",
                        addedAt: new Date()
                    };
                    await favoritesCollection.insertOne(newFavoriteDoc);
                    return res.json({ favorited: true, message: "Added to favorites collection successfully" });
                }
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal server error handling collection updates" });
            }
        });

        // ==========================================
        // 3. SUBMIT CONTENT REPORT API ROUTE
        // ==========================================
        app.post('/api/recipes/:id/report', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;
                const reporterEmail = req.user.email;
                const { reason } = req.body;

                if (!reason || !reason.trim()) {
                    return res.status(400).json({ message: "A descriptive violation reason statement is required" });
                }
                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ message: "Invalid Recipe ID targeting metrics" });
                }

                const reportDocument = {
                    recipeId: new ObjectId(recipeId),
                    reporterEmail,
                    reason: reason.trim(),
                    status: "pending",
                    createdAt: new Date()
                };

                await reportsCollection.insertOne(reportDocument);
                res.status(201).json({ success: true, message: "Report submitted successfully for evaluation" });
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal server error handling compliance filings" });
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