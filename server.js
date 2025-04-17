// Import thư viện cần thiết
const express = require("express");
const cors = require("cors");
const sql = require("mssql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

console.log("📦 ENV DB_USER:", process.env.DB_USER);


const app = express();
app.use(cors());
app.use(express.json());

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
    const isMatch = await bcrypt.compare(Password, user.Password);
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
    const hashedPassword = await bcrypt.hash(Password, 10);
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
        WHERE DeleteYn = 0
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




// 📌 Chạy server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
