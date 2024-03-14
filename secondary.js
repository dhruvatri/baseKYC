import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import multer from "multer";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();
let currentUser=0;

let cam = false; let adhaar=false; let pan=false; let complete=false;

async function getVerificationStatus()
{
  cam = false;  adhaar=false;  pan=false; complete=false;
  const result = await db.query("select * from kyc where userid=$1",[currentUser]);
  const status=result.rows[0];
  if (typeof(status.adhaar)!=undefined && status.adhaar!=null) adhaar=true;
  if (typeof(status.photo)!=undefined && status.photo!=null) cam=true; 
  if (typeof(status.pan)!=undefined && status.pan!=null) pan=true;
  console.log(cam);
  console.log(status.photo);
  complete=adhaar&& pan&&cam ; 
  console.log(status);
}

//multer setup
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//       cb(null, 'uploads/')
//   },
//   filename: function (req, file, cb) {
//       cb(null, file.originalname)
//   }
// });

// const upload = multer({ storage: storage });

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/dashboard",async(req, res) => {
  await getVerificationStatus();
  const uName = await db.query("select * from details where userid=$1",[currentUser]);
  res.render("dashboard.ejs",{user:uName.rows[0].name, adhaar:adhaar , pancard:pan , complete:complete , photo:cam});
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/details",
    failureRedirect: "/login",
  })
);

app.get("/camera", (req, res) => {
  // if (req.isAuthenticated()) {
    res.render("photo.ejs");
  // } else {
  //   res.redirect("/login");
  // }
});

app.get("/adhaar", (req, res) => {
  // if (req.isAuthenticated()) {
    res.render("adhaar.ejs");
  // } else {
  //   res.redirect("/login");
  // }
});
app.get("/pan", (req, res) => {
  // if (req.isAuthenticated()) {
    res.render("pan.ejs");
  // } else {
  //   res.redirect("/login");
  // }
});

app.get("/details", async(req, res) => {
   if (req.isAuthenticated()) {
    currentUser=req.user.id;
    const result = await db.query("select * from details where userid=$1",[currentUser]);
    console.log(result.rows);
    if (result.rows.length!=0) 
      res.redirect("/dashboard");
    else {
      res.render("details.ejs");
    }
  } else {
    res.redirect("/login");
  }
});

// app.post('/save-image', upload.single('image'), (req, res) => {
//   console.log('Image received and saved:', req.file);
//   res.sendStatus(200);
// });


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/details",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          await db.query(
            "INSERT INTO kyc (userid) VALUES ($1)",
            [result.rows[0].id]
          );
          currentUser=result.rows[0].id;
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/details");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/camera", async (req, res) => {
  await db.query("UPDATE kyc set photo='true' where userid=$1",[currentUser]);
  res.render('dashboard.ejs', {user:"Dhruv",photo:true});
});

app.post("/adhaar", async (req, res) => {
  const adhaar = (req.body.adhaarNumber);
  await db.query('update kyc set adhaar = $1 where userid=$2',[adhaar,currentUser]);
  res.redirect('/dashboard');
});

app.post("/pan", async (req, res) => {
  const pan = (req.body.panid);
  await db.query('update kyc set pan = $1 where userid=$2',[pan,currentUser]);
  res.redirect('/dashboard');
});

app.post("/details", async (req, res) => {
  const adhaar = (req.body);
  await db.query("INSERT INTO details VALUES ($1,$2,$3,$4,$5,$6)",[currentUser,adhaar.fullname,adhaar.dob,adhaar.address,adhaar.salaryRange,adhaar.employmentType]);
  res.redirect("/dashboard");
});



passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              currentUser=result.rows[0].id;
              console.log(currentUser);
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) returning *",
            [profile.email, "google"]
          );
          await db.query("INSERT INTO kyc values($1)",[newUser.rows[0].id]);
          currentUser=newUser.rows[0].id;
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
