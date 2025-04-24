// Import thư viện cần thiết
const express = require("express");
const multer = require("multer");
const path = require("path");
const router = express.Router();
const cors = require("cors");
const sql = require("mssql");
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
require("dotenv").config();

console.log("📦 ENV DB_USER:", process.env.DB_USER);


const app = express();
app.use(cors());
app.use(express.json());

app.use('/uploads', express.static('uploads'));


// Cấu hình kết nối SQL Server
const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: { encrypt: false, trustServerCertificate: true },
};

// Kết nối SQL Server
let pool;
async function connectDB() {
  try {
    pool = await sql.connect(config);
    console.log("✅ Kết nối SQL Server thành công!");
  } catch (err) {
    console.error("❌ Lỗi kết nối SQL Server:", err);
  }
}
connectDB();

// Cấu hình multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
})

const upload = multer({ storage });
//update profile
app.put("/update-profile", async (req, res) => {
  const { Username, Name, Email } = req.body;

  if (!Username || !Name || !Email) {
    return res.status(400).json({ error: "Thiếu thông tin cập nhật." });
  }

  try {
    await pool.request()
      .input("Name", sql.NVarChar, Name)
      .input("Email", sql.NVarChar, Email)
      .input("Username", sql.NVarChar, Username)
      .query(`
        UPDATE Users
        SET Name = @Name, Email = @Email
        WHERE Username = @Username
      `);

    const user = await pool.request()
      .input("Username", sql.NVarChar, Username)
      .query("SELECT * FROM Users WHERE Username = @Username");

    res.json({
      message: "Cập nhật thông tin thành công!",
      user: user.recordset[0],
    });
  } catch (err) {
    console.error("Lỗi cập nhật:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

//quen mat khau
app.post("/forgot-password", async (req, res) => {
  const { login, newPassword } = req.body;

  if (!login || !newPassword) {
    return res.status(400).json({ error: "Thiếu thông tin." });
  }

  try {
    const result = await pool
      .request()
      .input("login", sql.NVarChar, login)
      .query("SELECT * FROM Users WHERE Email = @login OR Username = @login");

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: "Không tìm thấy người dùng." });
    }

    const hashed = await bcryptjs.hash(newPassword, 10);

    await pool
      .request()
      .input("password", sql.NVarChar, hashed)
      .input("login", sql.NVarChar, login)
      .query("UPDATE Users SET Password = @password WHERE Email = @login OR Username = @login");

    res.json({ message: "Đổi mật khẩu thành công!" });
  } catch (err) {
    console.error("❌ Lỗi reset password:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// API Đăng nhập
app.post("/login", async (req, res) => {
  const { login, Password } = req.body;

  if (!login || !Password) {
    return res.status(400).json({ error: "Vui lòng nhập đầy đủ thông tin" });
  }

  try {
    const query = "SELECT * FROM Users WHERE Email = @login OR Username = @login";
    const result = await pool
      .request()
      .input("login", sql.NVarChar, login)
      .query(query);

    if (result.recordset.length === 0) {
      return res.status(401).json({ error: "Thông tin đăng nhập không hợp lệ" });
    }

    const user = result.recordset[0];
    const isMatch = await bcryptjs.compare(Password, user.Password);
    if (!isMatch) {
      return res.status(401).json({ error: "Thông tin đăng nhập không hợp lệ" });
    }

    const token = jwt.sign(
      { ID: user.ID, Username: user.Username, Email: user.Email, Role: user.Role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Đăng nhập thành công!",
      token,
      user: {
        ID: user.ID,
        Username: user.Username,
        Email: user.Email,
        Name: user.Name,
        Role: user.Role,
      }
    });
  } catch (err) {
    console.error("❌ Lỗi đăng nhập:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// API Đăng ký
app.post("/register", async (req, res) => {
  const { Name, Email, Username, Password } = req.body;

  if (!Name || !Email || !Username || !Password) {
    return res.status(400).json({ error: "Vui lòng nhập đầy đủ thông tin." });
  }

  try {
    const hashedPassword = await bcryptjs.hash(Password, 10);
    const checkUserQuery = "SELECT * FROM Users WHERE Username = @username OR Email = @email";
    const checkUser = await pool
      .request()
      .input("username", sql.NVarChar, Username)
      .input("email", sql.NVarChar, Email)
      .query(checkUserQuery);

    if (checkUser.recordset.length > 0) {
      return res.status(400).json({ error: "Tên đăng nhập hoặc email đã tồn tại." });
    }

    const insertQuery = "INSERT INTO Users (Name, Email, Username, Password) VALUES (@Name, @Email, @Username, @Password)";
    await pool
      .request()
      .input("Name", sql.NVarChar, Name)
      .input("Email", sql.NVarChar, Email)
      .input("Username", sql.NVarChar, Username)
      .input("Password", sql.NVarChar, hashedPassword)
      .query(insertQuery);

    res.status(201).json({ message: "Đăng ký thành công!" });
  } catch (err) {
    console.error("❌ Lỗi đăng ký:", err);
    res.status(500).json({ error: "Lỗi đăng ký", details: err.message });
  }
});

// API lấy danh sách món ăn
app.get("/recipes", async (req, res) => {
  try {
    const query = `
      SELECT 
        r.ID AS RecipeID,
        r.Title,
        r.Description,
        r.Image_url,
        r.Instruction,
        r.Created_at,
        r.Update_at,
        r.DeleteYn,
        r.User_id,
        u.Name AS Author,
        i.Name AS IngredientName,
        i.Unit,
        ri.Quantity
      FROM Recipes r
      JOIN Users u ON r.User_id = u.ID
      LEFT JOIN Recipe_Ingredients ri ON r.ID = ri.Recipe_id AND ri.DeleteYn = 0
      LEFT JOIN Ingredients i ON ri.Ingredient_id = i.ID AND i.DeleteYn = 0
      WHERE r.DeleteYn = 0
      ORDER BY r.Created_at DESC
    `;

    const result = await pool.request().query(query);
    const rows = result.recordset;

    const recipeMap = {};

    rows.forEach(row => {
      const {
        RecipeID, Title, Description, Image_url, Instruction,
        Created_at, Update_at, DeleteYn, User_id, Author,
        IngredientName, Quantity, Unit
      } = row;

      if (!recipeMap[RecipeID]) {
        recipeMap[RecipeID] = {
          RecipeID,
          Title,
          Description,
          Image_url,
          Instruction,
          Created_at,
          Update_at,
          DeleteYn,
          User_id,
          Author,
          Ingredients: []
        };
      }

      if (IngredientName) {
        recipeMap[RecipeID].Ingredients.push({
          Name: IngredientName,
          Quantity,
          Unit
        });
      }
    });

    const recipes = Object.values(recipeMap);
    res.status(200).json(recipes);

  } catch (err) {
    console.error("❌ Lỗi lấy danh sách món ăn:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// API lấy danh sách món ăn theo userID
app.get("/recipes/user/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const query = `SELECT 
        r.ID AS RecipeID,
        r.Title,
        r.Description,
        r.Image_url,
        r.Instruction,
        r.Created_at,
        r.Update_at,
        r.DeleteYn,
        r.User_id,
        u.Name AS Author,
        i.Name AS IngredientName,
        i.Unit,
        ri.Quantity
      FROM Recipes r
      JOIN Users u ON r.User_id = u.ID
      LEFT JOIN Recipe_Ingredients ri ON r.ID = ri.Recipe_id AND ri.DeleteYn = 0
      LEFT JOIN Ingredients i ON ri.Ingredient_id = i.ID AND i.DeleteYn = 0
      WHERE r.DeleteYn = 0 AND r.User_id = @userId
      ORDER BY r.Created_at DESC
    `;

    const result = await pool.request().input("userId", sql.Int, userId).query(query);    
    const rows = result.recordset;

    const recipeMap = {};

    rows.forEach(row => {
      const {
        RecipeID, Title, Description, Image_url, Instruction,
        Created_at, Update_at, DeleteYn, User_id, Author,
        IngredientName, Quantity, Unit  
      } = row;

      if (!recipeMap[RecipeID]) {
        recipeMap[RecipeID] = {
          RecipeID,
          Title,
          Description,
          Image_url,
          Instruction,
          Created_at,
          Update_at,
          DeleteYn,
          User_id,
          Author,
          Ingredients: []
        };
      }

      if (IngredientName) {
        recipeMap[RecipeID].Ingredients.push({
          Name: IngredientName,
          Quantity,
          Unit
        });
      }
    });

    const recipes = Object.values(recipeMap);
    res.status(200).json(recipes);

  } catch (err) {
    console.error("❌ Lỗi lấy danh sách món ăn:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// API lấy danh sách user
app.get("/users", async (req, res) => {
  try {
    const query = `SELECT 
      ID,
      Name,
      Username,
      Email,
      Active,
      Role
    FROM Users
    `;
    const result = await pool.request().query(query);
    res.status(200).json(result.recordset);
  } catch (err) {
    console.error("❌ Lỗi lấy danh sách user:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
})

// API xóa user
app.put("/users/delete/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input("userId", sql.Int, userId)
      .query(`
        UPDATE Users
        SET Active = 0
        WHERE ID = @userId;
      `);

    res.status(200).json({ message: "Xóa user thành công" });
  } catch (err) {
    console.error("Lỗi khi xóa user:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API mở khóa user
app.put("/users/active/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input("userId", sql.Int, userId)
      .query(`    
        UPDATE Users
        SET Active = 1
        WHERE ID = @userId;
      `);

    res.status(200).json({ message: "Mở khóa user thông" });
  } catch (err) {
    console.error("Lỗi khi mở khóa user:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API lấy danh sách nguyên liệu
app.get("/ingredients", async (req, res) => {
  try {
    const query = `SELECT 
      ID,
      Name,
      Unit
    FROM Ingredients
    WHERE DeleteYn = 0
    `;
    const result = await pool.request().query(query);
    res.status(200).json(result.recordset);
  } catch (err) {
    console.error("❌ Lỗi lấy danh sách nguyên liệu:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
})

// API xóa nguyên liệu
app.put("/ingredients/delete/:id", async (req, res) => {
  const ingredientId = req.params.id;

  try {
    const pool = await sql.connect(config);
    await pool.request()
      .input("ingredientId", sql.Int, ingredientId)
      .query(`
        UPDATE Ingredients
        SET DeleteYn = 1
        WHERE ID = @ingredientId;
      `);

    res.status(200).json({ message: "Xóa nguyên liệu thành công" });
  } catch (err) {
    console.error("Lỗi khi xóa nguyên liệu:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API đếm comment 
app.get("/recipes/:id/comments", async (req, res) => {
  const recipeId = req.params.id;

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input("recipeId", sql.Int, recipeId)
      .query(`
        SELECT 
            Recipe_id,
            COUNT(*) AS Comment_Count
        FROM Comments
        WHERE DeleteYn = 0 AND Recipe_id = @recipeId
        GROUP BY Recipe_id;
      `);

    if (result.recordset.length > 0) {
      res.json(result.recordset[0]); // Trả về object chứa Recipe_id và Comment_Count
    } else {
      res.json({ Recipe_id: recipeId, Comment_Count: 0 }); // Không có comment nào
    }
  } catch (err) {
    console.error("Error fetching comments count:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API lấy comment
app.get("/recipes/:id/comments/list", async (req, res) => {
  const recipeId = req.params.id;

  try {
    const result = await pool.request()
      .input("recipeId", sql.Int, recipeId)
      .query(`
        SELECT 
          c.ID AS CommentID,
          c.Comment_text,
          c.Created_at,
          u.Name AS Author,
          u.Avatar_url
        FROM Comments c
        JOIN Users u ON c.User_id = u.ID
        WHERE c.DeleteYn = 0 AND c.Recipe_id = @recipeId
        ORDER BY c.Created_at DESC
      `);

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error("Error fetching comments list:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API thêm comment
app.post("/recipes/:id/comments/add", async (req, res) => {
  const recipeId = req.params.id;
  const { userId, commentText } = req.body;

  if (!commentText) {
    return res.status(400).json({ error: "Hãy viết nội dung bạn muốn bình luận nào!" });
  }

  try {
    const result = await pool.request()
      .input("recipeId", sql.Int, recipeId)
      .input("userId", sql.Int, userId)
      .input("commentText", sql.NVarChar, commentText)
      .query(`
        INSERT INTO Comments (Recipe_id, User_id, Comment_text, Created_at, DeleteYn)
        VALUES (@recipeId, @userId, @commentText, GETDATE(), 0)
      `);

    res.status(201).json({ message: "Thêm comment thành công" });
  } catch (err) {
    console.error("Error adding comment:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API thêm món ăn
app.post("/recipes/add", upload.single("photo"), async (req, res) => {
  try {
    const {
      Title,
      Description,
      Instruction,
      User_id,
    } = req.body;

    const Ingredients = JSON.parse(req.body.Ingredients);
    const Image_url = req.file ? `uploads/${req.file.filename}` : null;
    const pool = await sql.connect(config);

    // 1. Thêm công thức vào bảng Recipes
    const insertRecipeResult = await pool.request()
      .input("Title", sql.NVarChar, Title)
      .input("Description", sql.NVarChar, Description)
      .input("Instruction", sql.NVarChar, Instruction)
      .input("Image_url", sql.NVarChar, Image_url)
      .input("User_id", sql.Int, User_id)
      .query(`
        INSERT INTO Recipes (Title, Description, Instruction, Image_url, Created_at, Update_at, User_id, DeleteYn)
        OUTPUT INSERTED.ID
        VALUES (@Title, @Description, @Instruction, @Image_url, GETDATE(), GETDATE(), @User_id, 0)
      `);

    const recipeId = insertRecipeResult.recordset[0].ID;

    // 2. Thêm từng nguyên liệu vào bảng Recipe_Ingredients
    for (const ingredient of Ingredients) {
      const { Name, Quantity, Unit } = ingredient;

      // Kiểm tra nguyên liệu đã có trong bảng Ingredients chưa
      const checkIngredient = await pool.request()
        .input("Name", sql.NVarChar, Name)
        .query(`
          SELECT ID FROM Ingredients WHERE Name = @Name AND DeleteYn = 0
        `);

      let ingredientId;

      if (checkIngredient.recordset.length > 0) {
        ingredientId = checkIngredient.recordset[0].ID;
      } else {
        const insertIngredient = await pool.request()
          .input("Name", sql.NVarChar, Name)
          .input("Unit", sql.NVarChar, Unit)
          .query(`
            INSERT INTO Ingredients (Name, Unit, DeleteYn)
            OUTPUT INSERTED.ID
            VALUES (@Name, @Unit, 0)
          `);

        ingredientId = insertIngredient.recordset[0].ID;
      }

      // Gắn nguyên liệu vào công thức
      await pool.request()
        .input("Recipe_id", sql.Int, recipeId)
        .input("Ingredient_id", sql.Int, ingredientId)
        .input("Quantity", sql.NVarChar, Quantity.toString())
        .query(`
          INSERT INTO Recipe_Ingredients (Recipe_id, Ingredient_id, Quantity, DeleteYn)
          VALUES (@Recipe_id, @Ingredient_id, @Quantity, 0)
        `);
    }

    res.status(201).json({ message: "Thêm công thức thành công!", RecipeID: recipeId });

  } catch (err) {
    console.error("❌ Lỗi khi thêm công thức:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});

// API cập nhật công thức
app.put("/recipes/update/:id", upload.single("photo"), async (req, res) => {
  try {
    const recipeId = req.params.id;
    const {
      Title,
      Description,
      Instruction,
      User_id,
    } = req.body;

    const Ingredients = JSON.parse(req.body.Ingredients);
    const Image_url = req.file ? `uploads/${req.file.filename}` : null;
    const pool = await sql.connect(config);

    const updateRecipeQuery = `
      UPDATE Recipes
      SET 
        Title = @Title,
        Description = @Description,
        Instruction = @Instruction,
        ${Image_url ? "Image_url = @Image_url," : ""}
        Update_at = GETDATE(),
        User_id = @User_id
      WHERE ID = @RecipeId
    `;

    const updateRequest = pool.request()
      .input("Title", sql.NVarChar, Title)
      .input("Description", sql.NVarChar, Description)
      .input("Instruction", sql.NVarChar, Instruction)
      .input("User_id", sql.Int, User_id)
      .input("RecipeId", sql.Int, recipeId);

    if (Image_url) {
      updateRequest.input("Image_url", sql.NVarChar, Image_url || null);
    }

    await updateRequest.query(updateRecipeQuery);

    await pool.request()
      .input("RecipeId", sql.Int, recipeId)
      .query(`DELETE FROM Recipe_Ingredients WHERE Recipe_id = @RecipeId`);

    for (const ingredient of Ingredients) {
      const { Name, Quantity, Unit } = ingredient;

      const checkIngredient = await pool.request()
        .input("Name", sql.NVarChar, Name)
        .query(`
          SELECT ID FROM Ingredients WHERE Name = @Name AND DeleteYn = 0
        `);

      let ingredientId;

      if (checkIngredient.recordset.length > 0) {
        ingredientId = checkIngredient.recordset[0].ID;
      } else {
        const insertIngredient = await pool.request()
          .input("Name", sql.NVarChar, Name)
          .input("Unit", sql.NVarChar, Unit)
          .query(`
            INSERT INTO Ingredients (Name, Unit, DeleteYn)
            OUTPUT INSERTED.ID
            VALUES (@Name, @Unit, 0)
          `);

        ingredientId = insertIngredient.recordset[0].ID;
      }

      await pool.request()
        .input("Recipe_id", sql.Int, recipeId)
        .input("Ingredient_id", sql.Int, ingredientId)
        .input("Quantity", sql.NVarChar, Quantity.toString())
        .query(`
          INSERT INTO Recipe_Ingredients (Recipe_id, Ingredient_id, Quantity, DeleteYn)
          VALUES (@Recipe_id, @Ingredient_id, @Quantity, 0)
        `);
    }

    res.status(200).json({ message: "Cập nhật công thức thành công!", RecipeID: recipeId });

  } catch (err) {
    console.error("❌ Lỗi khi cập nhật công thức:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});


// xóa công thức
app.put("/recipes/delete/:id", async (req, res) => {
  const { id } = req.params;
  try {
      const pool = await sql.connect(config);
      await pool
          .request()
          .input("id", sql.Int, id)
          .query("UPDATE Recipes SET DeleteYn = 1 WHERE ID = @id");

      res.status(200).json({ message: "Deleted successfully" });
  } catch (error) {
      console.error("Error deleting recipe:", error);
      res.status(500).json({ error: "Failed to delete recipe" });
  }
});

// tìm kiếm theo tên công thức hoặc tên nguyên liệu
app.get("/recipes/search", async (req, res) => {
  const keyword = req.query.q;

  if (!keyword) {
    return res.status(400).json({ error: "Vui lòng nhập từ khóa tìm kiếm." });
  }

  try {
    const query = `
      SELECT 
        r.ID AS RecipeID,
        r.Title,
        r.Description,
        r.Image_url,
        r.Instruction,
        r.Created_at,
        r.Update_at,
        r.DeleteYn,
        r.User_id,
        u.Name AS Author,
        i.Name AS IngredientName,
        i.Unit,
        ri.Quantity
      FROM Recipes r
      JOIN Users u ON r.User_id = u.ID
      LEFT JOIN Recipe_Ingredients ri ON r.ID = ri.Recipe_id AND ri.DeleteYn = 0
      LEFT JOIN Ingredients i ON ri.Ingredient_id = i.ID AND i.DeleteYn = 0
      WHERE r.DeleteYn = 0
        AND (
          LOWER(r.Title) LIKE '%' + LOWER(@keyword) + '%'
          OR LOWER(i.Name) LIKE '%' + LOWER(@keyword) + '%'
        )
      ORDER BY r.Created_at DESC
    `;

    const result = await pool
      .request()
      .input("keyword", sql.NVarChar, keyword)
      .query(query);

    const rows = result.recordset;
    const recipeMap = {};

    rows.forEach(row => {
      const {
        RecipeID, Title, Description, Image_url, Instruction,
        Created_at, Update_at, DeleteYn, User_id, Author,
        IngredientName, Quantity, Unit
      } = row;

      if (!recipeMap[RecipeID]) {
        recipeMap[RecipeID] = {
          RecipeID,
          Title,
          Description,
          Image_url,
          Instruction,
          Created_at,
          Update_at,
          DeleteYn,
          User_id,
          Author,
          Ingredients: []
        };
      }

      if (IngredientName) {
        recipeMap[RecipeID].Ingredients.push({
          Name: IngredientName,
          Quantity,
          Unit
        });
      }
    });

    const recipes = Object.values(recipeMap);
    res.status(200).json(recipes);

  } catch (err) {
    console.error("❌ Lỗi tìm kiếm công thức:", err);
    res.status(500).json({ error: "Lỗi server", details: err.message });
  }
});


// 📌 Chạy server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
