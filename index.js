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
    maxPoolSize: 10,
    minPoolSize: 2,
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

//  UPDATED: Added user assignment and fixed response key typos
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
        const userCollection = db.collection("user");

        // --- PUBLIC ROUTES ---

        //get user
        // 1. Get All Users Endpoint (Restricted to Admin)
        app.get('/api/users', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                // Fetch all users to calculate total count and premium distributions on client side
                const users = await userCollection.find({}).toArray();
                res.status(200).json(users);
            } catch (error) {
                console.error("Error pulling platform users matrix:", error);
                res.status(500).json({ message: "Internal server error compilation failed." });
            }
        });

        // 2. Get All Reports Endpoint (Restricted to Admin)
        app.get('/api/reports', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                // Fetch all community report flags for dashboard verification lengths
                const reports = await reportsCollection.find({}).toArray();
                res.status(200).json(reports);
            } catch (error) {
                console.error("Error pulling system reports matrix:", error);
                res.status(500).json({ message: "Internal server error compilation failed." });
            }
        });

        // Update User Block Status Endpoint
        app.patch('/api/users/:id/block', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                const { id } = req.params;
                const { isBlocked } = req.body; // Expects a boolean: true or false

                const result = await userCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            isBlocked: Boolean(isBlocked),
                            updatedAt: new Date()
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "User profile not found." });
                }

                res.status(200).json({
                    success: true,
                    message: `User successfully ${isBlocked ? 'blocked' : 'unblocked'}.`
                });
            } catch (error) {
                console.error("Error updating user access matrix:", error);
                res.status(500).json({ message: "Internal server error blocking execution." });
            }
        });

        //get all recipes for everyone
        app.get('/api/recipes', async (req, res) => {
            try {
                const query = {};

                // Existing filters
                if (req.query.authorId) query.authorId = req.query.authorId;
                if (req.query.status) query.status = req.query.status;

                // New Database filters
                if (req.query.category) query.category = req.query.category;
                if (req.query.cuisineType) query.cuisineType = req.query.cuisineType;

                // Pagination setup
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 8; // Change default size if desired
                const skip = (page - 1) * limit;

                // Fetch paginated data and total count concurrently
                const [recipes, totalCount] = await Promise.all([
                    recipesCollection.find(query).skip(skip).limit(limit).toArray(),
                    recipesCollection.countDocuments(query)
                ]);

                const totalPages = Math.ceil(totalCount / limit);

                res.send({
                    recipes,
                    pagination: {
                        totalCount,
                        totalPages,
                        currentPage: page,
                        limit
                    }
                });
            } catch (error) {
                console.error("Error fetching recipes:", error);
                res.status(500).send({ error: "Internal server error occurred." });
            }
        });
        // Secure Private Route: Fetch recipes created exclusively by the logged-in user
        app.get('/api/user/my-recipes', verifyToken, async (req, res) => {
            try {
                // Extracted directly from your verifyToken middleware payload
                const userId = req.user.id;
                const userRecipes = await recipesCollection.find({ authorId: userId }).toArray();

                res.status(200).json(userRecipes);
            } catch (error) {
                console.error("Error pulling account recipe matrix:", error);
                res.status(500).json({ message: "Internal server error compilation failed." });
            }
        });

        // Scoped path to prevent route duplication collisions. it is for edit recipe.
        app.get('/api/user/my-recipes/:id', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;
                const userId = req.user.id;

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ message: "Invalid recipe ID format." });
                }

                const recipe = await recipesCollection.findOne({ _id: new ObjectId(recipeId) });

                if (!recipe) {
                    return res.status(404).json({ message: "Recipe not found." });
                }

                // Strict Ownership enforcement for management access
                if (recipe.authorId !== userId) {
                    return res.status(403).json({ message: "Unauthorized: You do not own this recipe." });
                }

                res.status(200).json(recipe);
            } catch (error) {
                console.error("Error fetching recipe for edit workspace:", error);
                res.status(500).json({ message: "Internal server error." });
            }
        });

        // Look for your PUT or PATCH route around line 170-200
        app.patch('/api/recipes/:id', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;
                const body = req.body;

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ error: "Invalid Recipe ID format." });
                }
                const result = await recipesCollection.findOneAndUpdate(
                    { _id: new ObjectId(recipeId) },
                    {
                        $set: {
                            recipeName: body.recipeName,
                            recipeImage: body.recipeImage,
                            category: body.category,
                            cuisineType: body.cuisineType,
                            difficultyLevel: body.difficultyLevel,
                            preparationTime: Number(body.preparationTime) || 0,
                            description: body.description,
                            ingredients: body.ingredients,
                            instructions: body.instructions
                        }
                    },
                    { returnDocument: 'after' }
                );

                const updatedDoc = result?.value || result;
                if (!updatedDoc) {
                    return res.status(400).json({ error: "Failed to update database record." });
                }

                return res.status(200).json({ success: true, data: updatedDoc });

            } catch (error) {
                console.error("❌ Update Recipe Error:", error.message);
                return res.status(500).json({ error: "Internal server error during update." });
            }
        });

        // Clean and Hybrid: Accessible by everyone, but tracks state for logged-in accounts
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
        // Admin recipe fetch endpoint
        app.get('/api/admin/recipes/:id', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                const recipeId = req.params.id;

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ message: "Invalid recipe ID format." });
                }

                const recipe = await recipesCollection.findOne({ _id: new ObjectId(recipeId) });

                if (!recipe) {
                    return res.status(404).json({ message: "Recipe not found." });
                }

                res.status(200).json(recipe);
            } catch (error) {
                console.error("Admin Error fetching recipe:", error);
                res.status(500).json({ message: "Internal server error." });
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
        // backend index.js
        app.post('/api/recipes/:id/favorite', verifyToken, async (req, res) => {
            try {
                const recipeId = req.params.id;
                const userId = req.user.id;
                const userEmail = req.user.email;

                // FIX: Extract the properties from inside the nested object node
                const { recipeName, recipeImage, category, cuisineType } = req.body.favoriteRecipeData || {};

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ message: "Invalid Recipe ID format" });
                }

                const recipeObjectId = new ObjectId(recipeId);
                const favoriteQuery = { recipeId: recipeObjectId, userId: userId };
                const existingFavorite = await favoritesCollection.findOne(favoriteQuery);

                if (existingFavorite) {
                    await favoritesCollection.deleteOne(favoriteQuery);
                    return res.json({ favorited: false, message: "Removed from favorites" });
                } else {
                    const newFavoriteDoc = {
                        userId,
                        userEmail,
                        recipeId: recipeObjectId,
                        recipeName,     // Now successfully populated!
                        recipeImage,    // Now successfully populated!
                        category,       // Now successfully populated!
                        cuisineType,    // Now successfully populated!
                        createdAt: new Date()
                    };
                    await favoritesCollection.insertOne(newFavoriteDoc);
                    return res.json({ favorited: true, message: "Added to favorites successfully" });
                }
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal server error" });
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

        // app.delete('/api/recipes/:id', verifyToken, async (req, res) => {
        //     try {
        //         const recipeId = req.params.id;

        //         if (!ObjectId.isValid(recipeId)) {
        //             return res.status(400).json({ error: "Invalid Recipe ID format." });
        //         }

        //         const existingRecipe = await recipesCollection.findOne({ _id: new ObjectId(recipeId) });

        //         if (!existingRecipe) {
        //             return res.status(404).json({ error: "Recipe not found in records." });
        //         }

        //         if (existingRecipe.userEmail !== req.user?.email) {
        //             return res.status(403).json({ error: "Access Denied: You do not own this recipe blueprint." });
        //         }
        //         const result = await recipesCollection.deleteOne({ _id: new ObjectId(recipeId) });

        //         if (result.deletedCount === 0) {
        //             return res.status(400).json({ error: "Failed to delete the recipe record." });
        //         }

        //         return res.status(200).json({ success: true, message: "Recipe deleted successfully from the database." });

        //     } catch (error) {
        //         console.error("❌ Delete Recipe Error:", error.message);
        //         return res.status(500).json({ error: "Internal server error during deletion." });
        //     }
        // });
        app.delete('/api/recipes/:id', verifyToken, authorizeRoles("user"), async (req, res) => {
            try {
                const recipeId = req.params.id;

                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ error: "Invalid Recipe ID format." });
                }

                const result = await recipesCollection.deleteOne({ _id: new ObjectId(recipeId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ error: "Recipe not found or already deleted." });
                }

                return res.status(200).json({ success: true, message: "Recipe deleted successfully from the database." });

            } catch (error) {
                console.error("❌ Delete Recipe Error:", error.message);
                return res.status(500).json({ error: "Internal server error during deletion." });
            }
        });

        //get favorite recipe accourding to user
        app.get('/api/user/my-favorite', verifyToken, async (req, res) => {
            try {
                // Extracted directly from your verifyToken middleware payload
                const userId = req.user.id;
                const userRecipes = await favoritesCollection.find({ userId }).toArray();

                res.status(200).json(userRecipes);
            } catch (error) {
                console.error("Error pulling account recipe matrix:", error);
                res.status(500).json({ message: "Internal server error compilation failed." });
            }
        });
        // delete fovirate for user dashboard.
        // --- Action: Remove Recipe from Favorites ---
        app.delete('/api/user/my-favorite/:id', verifyToken, async (req, res) => {
            try {
                const favoriteId = req.params.id;
                const userId = req.user.id;

                // 1. Validate the incoming ID structure
                if (!ObjectId.isValid(favoriteId)) {
                    console.error(`Rejected invalid ObjectId payload: "${favoriteId}"`);
                    return res.status(400).json({
                        success: false,
                        message: `Malformatted ID context received: "${favoriteId}". Must be a 24-character hex string.`
                    });
                }

                // 2. Perform safe deletion
                const result = await favoritesCollection.deleteOne({
                    _id: new ObjectId(favoriteId),
                    userId: userId
                });

                if (result.deletedCount === 1) {
                    return res.status(200).json({ success: true, message: "Removed from favorites successfully." });
                } else {
                    return res.status(404).json({ success: false, message: "Favorite record not found." });
                }
            } catch (error) {
                console.error("Error deleting favorite item:", error);
                return res.status(500).json({ success: false, message: "Internal server error occurred." });
            }
        });

        // PATCH Route: Update specific administrative parameters of a recipe
        app.patch('/api/admin/recipes/:id', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                const recipeId = req.params.id;
                const { isFeatured, status } = req.body;

                // 1. Validate ObjectId structure
                if (!ObjectId.isValid(recipeId)) {
                    return res.status(400).json({ success: false, message: "Invalid recipe ID format structure." });
                }

                // 2. Build dynamic payload allocation block to prevent arbitrary overwrites
                const updateData = {};

                if (isFeatured !== undefined) {
                    updateData.isFeatured = Boolean(isFeatured);
                }

                if (status !== undefined) {
                    // Validation guard rail to only accept system defined status constraints
                    if (status === 'pending' || status === 'allowed') {
                        updateData.status = status;
                    } else {
                        return res.status(400).json({ success: false, message: "Invalid status selection type." });
                    }
                }

                // 3. Fallback protection: check if there's actually a payload body array
                if (Object.keys(updateData).length === 0) {
                    return res.status(400).json({ success: false, message: "No modifiable schema parameters specified in the request body." });
                }

                // Timestamp injection tracker updates
                updateData.updatedAt = new Date().toISOString();

                // 4. Update the record within MongoDB database collections
                const result = await recipesCollection.updateOne(
                    { _id: new ObjectId(recipeId) },
                    { $set: updateData }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: "Recipe document matrix could not be resolved." });
                }

                res.status(200).json({
                    success: true,
                    message: "Recipe parameters altered successfully inside database schema block.",
                    updatedFields: updateData
                });

            } catch (error) {
                console.error("Administrative database update operational breakdown:", error);
                res.status(500).json({ success: false, message: "Internal server error execution breakdown." });
            }
        });

        const { ObjectId } = require('mongodb'); // ensure ObjectId is imported

        // PATCH Route: Update report state matrix (e.g., Dismissing a flag)
        app.patch('/api/reports/:id', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                const reportId = req.params.id;
                const { status } = req.body;

                // Validate target parameter structure
                if (!ObjectId.isValid(reportId)) {
                    return res.status(400).json({ success: false, message: "Invalid report ID format configuration." });
                }

                // Limit input array manipulation to permitted status fields
                if (!status || !['pending', 'dismissed'].includes(status)) {
                    return res.status(400).json({ success: false, message: "Invalid status state transition requested." });
                }

                // Execute structural modification update against MongoDB
                const result = await reportsCollection.updateOne(
                    { _id: new ObjectId(reportId) },
                    {
                        $set: {
                            status: status,
                            updatedAt: new Date()
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: "Target validation report ticket not found." });
                }

                res.status(200).json({
                    success: true,
                    message: `Report status successfully adjusted to ${status}.`
                });

            } catch (error) {
                console.error("Error patching moderation records:", error);
                res.status(500).json({ success: false, message: "Internal server error state alteration failed." });
            }
        });

        // DELETE Route: Erase a report ticket entry completely
        app.delete('/api/reports/:id', verifyToken, authorizeRoles('admin'), async (req, res) => {
            try {
                const reportId = req.params.id;

                // Validate target parameter structure
                if (!ObjectId.isValid(reportId)) {
                    return res.status(400).json({ success: false, message: "Invalid report ID format configuration." });
                }

                // Perform final destruction query inside data array collection blocks
                const result = await reportsCollection.deleteOne({ _id: new ObjectId(reportId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ success: false, message: "Target report timeline instance not resolved." });
                }

                res.status(200).json({
                    success: true,
                    message: "Report log permanently dropped from global infrastructure tracking."
                });

            } catch (error) {
                console.error("Error clearing moderation index entry:", error);
                res.status(500).json({ success: false, message: "Internal server error record destruction failed." });
            }
        });


        // // Check database connectivity
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