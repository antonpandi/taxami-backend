const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require('dotenv').config();
const bcrypt = require("bcryptjs");
const hashSecret = process.env["secret"];
const hash = bcrypt.hashSync(hashSecret, 12);
const mysql = require("mysql2");
let conn = "";
let connPromise = "";

connectToDatabase();

const app = express();
app.listen(3000);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors({ credentials: true, origin: true }));
// app.use(cors({ credentials: true, origin: "*" }));

app.use(cookieParser());

//GET Routes
app.get("/user", authToken, getUser);
app.get("/clients", getAllClients);
app.get("/workers", getAllWorkers);
app.get("/buildings/all", getAllBuildings);
app.get("/assignments/all", getAllAssignments);
app.get("/assignments/available", getAllAvailableAssignments);
app.get("/find/client", findClient);

//POST Routes
app.post("/login/client", clientLogin);
app.post("/login/worker", workerLogin);
// app.post("/add/client", authToken, addClient);
// app.post("/add/worker", authToken, addWorker);
app.post("/add/client", addClient);
app.post("/add/worker", addWorker);
app.post("/add/buildings", authToken, addBuilding);
app.post("/add/assignments", authToken, addAssignment);
app.post("/building", getBuilding);
app.post("/building/assignments", getBuildingAssignments);
app.post("/building/workers", getWorkers);
app.post("/link/buildings", authToken, linkWorkerToBuilding);
app.post("/link/workers", authToken, linkWorkerToClient);
app.post("/get/worker", getWorker);

//DELETE Routes
app.delete("/remove/client", removeClient);
app.delete("/remove/worker", removeWorker);
app.delete("/remove/buildings", removeBuilding);

//PUT Routes
app.put("/edit/client", editClient);
app.put("/edit/worker", editWorker);
app.put("/edit/buildings", editBuilding);
app.put("/edit/assignments", editAssignment);
app.put("/assignments/takeon", takeOnAssignment);
app.put("/assignments/drop", dropAssignment);
app.put("/assignments/complete", completeAssignment);
app.put("/assignments/uncomplete", uncompleteAssignment);

//Middleware
function connectToDatabase() {
  //Databas connection
  conn = mysql.createPool({
    host: process.env["db_host"],
    user: process.env["db_user"],
    database: process.env["db_name"],
    password: process.env["db_password"],
  });

  connPromise = conn.promise();

  if (conn) console.log("Connected to Database");

  conn.on("error", (err) => {
    console.error("Connetion Error: ", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST") {
      connectToDatabase();
    }
  });
}

async function getData(query, props){

}

async function authToken(req, res, next) {
  console.log("HEader: ", req.cookies.accessToken);
  const token = req.cookies.accessToken;

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error({ error: err.message });
      console.error("User was not authenticated")
      res.redirect("/login");
      return res.sendStatus(403);
    }
    console.log("User: ", user);
    req.user = user;
    next();
  });
}

async function authAdmin(req, res, next) {}

async function authClient(req, res, next) {}

async function authWorker(req, res, next) {}

async function hashPassword(password) {
  //Encrypt password
  try {
    password = await bcrypt.hash(password, 12);
    return password;
  } catch (err) {
    return res.send(err);
  }
}

function sendMail(text) {
  console.log("Temp mail functio", text);
}

//GET Functions

async function getUser(req, res) {
  const token = req.cookies.accessToken;
  console.log("Token: ", token);

  let claims = jwt.verify(token, process.env["ACCESS_TOKEN_SECRET"]);
  console.log("Claims: ", claims);

  if (!claims) {
    return res.status(401).send({
      message: "Unauthenticated",
    });
  }

  const [user, fields] = await connPromise.execute(
    "SELECT * FROM users WHERE id = ?",
    [claims.id],
  );

  console.log(user);

  res.send(user[0]);
}

async function getAllClients(req, res) {
  //if(!req.user.role == "ADMIN") res.sendStatus(403).json({mes: "Unauthorized access"});

  let query = "SELECT * FROM users WHERE role = 'CLIENT'";

  let [rows, fields] = await connPromise.execute(query);

  if (rows.length > 0)
    res.json({ mes: "Successfully found Clients", users: rows });
  else res.json({ mes: "No Clients was found" });
}

async function getAllWorkers(req, res) {
  let query = "SELECT * FROM workers WHERE role = 'WORKER'";

  let [rows, fields] = await connPromise.execute(query);

  if (rows.length > 0)
    res.json({ mes: "Successfully found Workers", workers: rows });
  else res.json({ mes: "No Clients was found" });
}

async function getAllBuildings(req, res) {
  let query = "SELECT * FROM buildings";

  try {
    const [buildings, fields] = await connPromise.execute(query)

    console.log("result: ", buildings);
    res.json(buildings) 
  } catch (error) {
    res.json({mes: "No builds found"})
  }

}

async function getAllAssignments(req, res) {
  let query = "SELECT * FROM assignments";

  await conn.execute(query, (err, result) => {
    if (err) res.json({ mes: err });
    if (result)
      res.json({ mes: "Successfully found assignments", result: result });
    else res.json({ mes: "No assignments was found" });
  });
}

async function getAllAvailableAssignments(req, res) {
  let query =
    "SELECT * FROM assignments WHERE building = (SELECT building_id FROM worker_building where user_id = ?) ";

  let [rows, fields] = await connPromise.execute(query, [req.user.id]);

  if (rows.length > 0)
    res.json({ mes: "Successfully found Assignments", users: rows });
  else res.json({ mes: "No Assignments was found" });
}

async function findClient(req, res) {
  const { email } = req.body;
  console.log("Body: ", req.body);
  const query = `SELECT * FROM users WHERE email = ? limit 1`;
  try {
    conn.execute(query, [email.trim()], (err, user) => {
      console.log("User: ", user);

      if (user.length < 1) res.json({ mes: "No user found" });
      res.json(user);
    });
  } catch (err) {
    res.json({ mes: err.message });
  }
}

function getMyWorkers(req, res) {}

//POST Functions
async function clientLogin(req, res) {
  console.log("Body: ", req.body);
  let email = req.body.email.trim();
  let password = req.body.password.trim();
  let user = "";

  let query = `SELECT * FROM users WHERE email = ? LIMIT 1`;

  try {

    conn.execute(query, [email], async (err, result) => {
      if (err) throw err;
      let user = result[0];
      console.log("Result: ", result, "User: ", user);

      if (!bcrypt.compareSync(password, user.password)) res.sendStatus(403);

      const accessToken = jwt.sign(user, process.env["ACCESS_TOKEN_SECRET"]);
      if (!accessToken) {
        return res.status(500).json({ mes: "Token error" });
      }
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });
      console.log("AccessToken: ", accessToken);

      delete user.password;

      res.json({ accessToken: accessToken, user: user, cookies: res.cookie });
    });
  } catch (err) {
    res.json({ err: err.message });
  }
}

async function workerLogin(req, res) {
  console.log(req.body.email);
  let email = req.body.email.trim();
  let password = req.body.password.trim();
  let role = req.body.role;
  let user = "";

  let query = `SELECT * FROM workers WHERE email = ? AND ROLE = ? LIMIT 1 `;
  try {
    conn.execute(query, [email, role], async (err, result) => {
      if (err) throw err;
      let user = result[0];
      console.log("Result: ", result, "User: ", user);

      const accessToken = jwt.sign(user, process.env["ACCESS_TOKEN_SECRET"]);
      if (!accessToken) return res.status(500).json({ mes: "Token error" });
      res.cookie("accessToken", accessToken, {
        HttpOnly: true,
        Secure: true,
        SameSite: "None",
      });
      res.json({ accessToken: accessToken, cookies: res.cookie });
    });
  } catch (err) {
    res.json({ err: err.message });
  }
}

async function addClient(req, res) {
  console.log("body", req.body);
  //Something was posted
  let { fname, lname, email, password, role } = req.body;
  role = "CLIENT";

  if (checkEmail(email)) res.json({ mes: "Email already in use" });

  //Encrypt password
  //password = hashPassword(password);

  console.log(
    "fname: ", fname,
    "lname: ", lname,
    "email: ", email,
    "password: ", password,
  );

  if (fname && lname && password) {

    //Save to database
    try {
      let userQuery = [
        fname.trim(),
        lname.trim(),
        email.trim(),
        await hashPassword(password.trim()),
        role,
      ];
      console.log("userQuery");
      let query = `
    INSERT INTO users(
      fname,
      lname,
      email,
      password,
      role
    ) values(?, ?, ?, ?, ?)`;

      console.log("Query: ", query, userQuery);
      conn.execute(query, userQuery, (err, result) => {
        if (err) res.json({ mes: err.message, err: err, result: result });
        else res.json({ mes: result });
      });
    } catch (err) {
      console.error(err);
      res.json(err);
    }
  } else {
    res.send("Please enter your username and password");
  }
}

async function addWorker(req, res) {
  console.log("body", req.body);
  //Something was posted
  let { fname, lname, email, role } = req.body;
  role = "WORKER";

  console.log("fname: ", fname, "lname: ", lname, "email: ", email);

  if (fname && lname && email) {
    //Save to database
    try {
      let userQuery = [fname.trim(), lname.trim(), email.trim(), role];
      console.log("userQuery");
      let query = `
    INSERT INTO workers(
      fname,
      lname,
      email,
      role
    ) values(?, ?, ?, ?)`;

      console.log("Query: ", query, userQuery);
      conn.execute(query, userQuery, (err, result) => {
        if (err) res.json({ mes: err.message, err: err, result: result });
        else res.json({ mes: result });
      });
    } catch (err) {
      console.error(err);
      res.json(err);
    }
  } else {
    res.send("Please enter your username and password");
  }
}

async function addUser(req, res) {
  console.log("body", req.body);
  //Something was posted
  let { fname, lname, email, password, role } = req.body;
  role = "CLIENT";

  if (checkEmail(email)) res.json({ mes: "Email already in use" });

  //Encrypt password
  //password = hashPassword(password);

  console.log(
    "fname: ", fname,
    "lname: ", lname,
    "email: ", email,
    "password: ", password,
  );

  if (fname && lname) {

    //Save to database
    try {
      //Create user array
      let params = [];
      let query = "";

        params = [
          fname.trim(),
          lname.trim(),
          email.trim(),
          role,
        ];

      if(role=="CLIENT") params.splice(3, 0 , await hashPassword(password.trim()));
    
      if(role = "CLIENT"){
        query = `
          INSERT INTO users(
            fname,
            lname,
            email,
            password,
            role
          ) values(?, ?, ?, ?, ?)`;
      }
      else{
        query = `
        INSERT INTO users(
          fname,
          lname,
          email,
          role
        ) values(?, ?, ?, ?)`;
      }

      await connPromise.execute(query, params);

    } catch (err) {
      console.error(err);
      res.json(err);
    }
  } else {
    res.send("Please enter your username and password");
  }
}

function addBuilding(req, res) {
  let { type, adress } = req.body;
  let userQuery = [req.user.id, type.trim(), adress.trim()];
  let query = `INSERT INTO buildings(
  user_id,
  type,
  adress
  ) VALUES(?, ?, ?)`;

  conn.execute(query, userQuery, (err, result) => {
    if (err) res.json({ mes: err.message });
    res.json({ mes: "building added", result: result });
  });
}

function addAssignment(req, res) {
  console.log(req.body);
  let userQuery = Object.values(req.body);
  userQuery.unshift(req.user.id);
  console.log("Assignment: ", userQuery);

  let query = `INSERT INTO assignments (
  client_id,
  worker_id,
  building_id,
  title,
  description,
  priority,
  deadline
  ) values(?, ?, ?, ?, ?, ?, ?,)`;
  try {
    conn.execute(query, userQuery, (err, result) => {
      if (err) {
        res.json({ mes: err });
      }
      if (result.affectedRows > 0) res.json({ mes: "Assignment was posted" });
      else res.json({ mes: "Assignment was not posted" });
    });
  } catch (err) {
    console.error(err);
  }
}

function linkWorkerToBuilding(req, res) {
  let { worker_id, building_id } = req.body;

  query = "INSERT INTO worker_building(worker_id, building_id) VALUES(?, ?)";
  conn.execute(query, [user_id, building_id], (err, result) => {
    if (err) res.json({ mes: err.message, err: err, result: result });
    res.json({ mes: "Worker linked to building", result: result });
  });
}

function linkWorkerToClient(req, res) {
  let { worker_email } = req.body;
  let query = "SELECT id FROM users WHERE email = ?";

  let { rows, feilds } = connPromise.execute(query, [worker_email]);
  let worker = rows[0];

  query = "INSERT INTO user_worker(user_id, building_id) VALUES(?, ?)";
  conn.execute(query, [req.user.id, worker.id], (err, result) => {
    if (err) res.json({ mes: err.message, err: err, result: result });
    res.json({ mes: "user linked to building", result: result });
  });
}

async function getBuilding(req, res){
  console.log("Body: ", req.body)
  let id = req.body.id;
  const [buildings, rows] = await connPromise.execute("SELECT * FROM buildings WHERE id = ?", [id])
  res.json({building:buildings[0]});
}

async function getBuildingAssignments(req, res){
  console.log("Body: ", req.body)
  let id = req.body.id;
  const [assignments, rows] = await connPromise.execute("SELECT * FROM assignments WHERE building_id = ?", [id])
  console.log("Assignments: ", assignments)
  res.json({assignments});
}

async function getWorker(req, res){
  console.log(req.body)
  let id = req.body.id;
  const [workers, rows] = await connPromise.execute("SELECT * FROM workers WHERE id = ?", [id])
  res.json({worker:workers[0]});
}

async function getWorkers(req, res){
  console.log(req.body)
  let building = req.body.building;
  const [workers, rows] = await connPromise.execute("SELECT * FROM workers WHERE id IN (SELECT worker_id FROM worker_building WHERE building_id = ?)", [building.id])
  res.json({workers});
}

//DELETE Functions
async function removeClient(req, res) {
  const { email } = req.body;
  const query = `DELETE FROM users WHERE email = ? `;
  try {
    await conn.execute(query, [email], (err, result) => {
      if (err) res.json({ men: err });

      if (result.affectedRows > 0)
        res.json({ mes: "User removed", user: req.body });
      else res.json({ mes: "User did not exist" });
    });
  } catch (err) {
    res.json({ mes: err.message });
  }
}

async function removeWorker(req, res) {
  const { email } = req.body;
  const query = `DELETE FROM workers WHERE email = ? `;
  try {
    await conn.execute(query, [email], (err, result) => {
      if (err) res.json({ men: err });

      if (result.affectedRows > 0)
        res.json({ mes: "Worker removed", user: req.body });
      else res.json({ mes: "Worker did not exist" });
    });
  } catch (err) {
    res.json({ mes: err.message });
  }
}

async function removeBuilding(req, res) {
  let userQuery = [req.body.id];

  const query = "DELETE FROM buildings WHERE id = ?";
  try {
    await conn.execute(query, userQuery, (err, result) => {
      if (err) res.json({ mes: err, result: result });
      if (result.affectedRows > 0) res.json({ mes: "Building removed" });
      else res.json({ mes: "No building was found/removed" });
    });
  } catch (error) {
    console.error(error);
  }
}

async function removeAssigment(req, res) {
  let userQuery = [req.body.id];

  const query = "DELETE FROM assignments WHERE id = ?";
  try {
    await conn.execute(query, userQuery, (err, result) => {
      if (err) res.json({ mes: err, result: result });
      if (result.affectedRows > 0) res.json({ mes: "Assigment removed" });
      else res.json({ mes: "No assignment was found/removed" });
    });
  } catch (error) {
    console.error(error);
  }
}

//UPADTE Functions
async function editClient(req, res) {
  let query = "SELECT * FROM users where id = ? LIMIT 1";
  console.log("Body: ", req.body);

  const [rows, fields] = await connPromise.execute(query, [req.body.user.id]);

  let user = rows[0];
  let updatedUser = { ...user, ...req.body.user };
  let { fname, lname, email, password, id } = updatedUser;
  //Make an array in the correct oreder for SQL
  let queryArray = [email, fname, lname, password, id];

  try {
    query =
      "UPDATE users SET email = ?, fname = ?, lname =?, password = ? WHERE id = ?";

    conn.execute(query, queryArray, (err, result) => {
      if (err) res.json({ mes: err });

      if (result.affectedRows > 0)
        res.json({ mes: "User was updated", result: result });
      else res.json({ mes: "Could not update user", result: result });
    });
  } catch (error) {
    res.json({ mes: error });
  }
}

async function editWorker(req, res) {
  let query = "SELECT * FROM workers where id = ? LIMIT 1";

  const [rows, fields] = await connPromise.execute(query, [req.body.id]);

  let user = rows[0];
  let updatedUser = { ...user, ...req.body };
  let { fname, lname, email, id } = updatedUser;
  //Make an array in the correct oreder for SQL
  let queryArray = [email, fname, lname, id];

  try {
    query =
      "UPDATE users SET email = ?, fname = ?, lname =?, password = ? WHERE id = ?";

    conn.execute(query, queryArray, (err, result) => {
      if (err) res.json({ mes: err });

      if (result.affectedRows > 0)
        res.json({ mes: "User was updated", result: result });
      else res.json({ mes: "Could not update user", result: result });
    });
  } catch (error) {
    res.json({ mes: error });
  }
}

async function editBuilding(req, res) {
  try {
    let query = "SELECT * FROM buildings where id = ? LIMIT 1";

    const [rows, fields] = await connPromise.execute(query, [req.body.id]);

    let building = rows[0];
    let updatedBuilding = { ...building, ...req.body };
    let { type, adress, id } = updatedBuilding;

    //Make an array in the correct oreder for SQL
    let queryArray = [type, adress, id];

    query = "UPDATE buildings SET type = ?, adress = ? WHERE id = ?";
    await conn.execute(query, queryArray, (err, result) => {
      if (err) res.json({ mes: err });
      if (result.affectedRows > 0)
        res.json({ mes: "Building was successfully updated", result: result });
      else res.json({ mes: "Building failed to update", result: result });
    });
  } catch (error) {
    res.json({ mes: error });
    console.error(error);
  }
}

async function editAssignment(req, res) {
  try {
    let query = "SELECT * FROM assignments where id = ? LIMIT 1";

    const [rows, fields] = await connPromise.execute(query, [req.body.id]);

    let assignment = rows[0];
    let updatedAssignment = { ...assignment, ...req.body };
    let {
      id,
      client_id,
      building_id,
      title,
      description,
      estimated_time,
      estimated_cost,
      total_time,
      total_cost,
      priority,
      deadline,
      comment,
    } = updatedAssignment;

    //Make an array in the correct oreder for SQL
    let queryArray = [
      client_id,
      building_id,
      title,
      description,
      estimated_time,
      estimated_cost,
      total_time,
      total_cost,
      priority,
      deadline,
      comment,
      id,
    ];

    query = `UPDATE assignments SET 
        client_id = ?,
        building_id = ?,
        title = ?,
        description = ?,
        estimated_time = ?,
        estimated_cost = ?,
        total_time = ?,
        total_cost = ?,
        priority = ?,
        deadline = ?,
        comment = ? 
        WHERE id = ?`;

    await conn.execute(query, queryArray, (err, result) => {
      if (err) res.json({ mes: err, result: result });
      if (result.affectedRows > 0)
        res.json({
          mes: "Assignment was successfully updated",
          result: result,
        });
      else res.json({ mes: "Assignment failed to update", result: result });
    });
  } catch (error) {
    res.json({ mes: error });
    console.error(error);
  }
}

function takeOnAssignment(req, res) {
  const { worker_id, estimated_time, estimated_cost, assignment_id } = req.body;
  const queryArray = [worker_id, estimated_time, estimated_cost, assignment_id];

  console.log(queryArray);

  let query = `UPDATE assignments 
  SET worker_id = ?, 
  estimated_time = ?,
  estimated_cost = ?
  WHERE id = ?`;

  conn.execute(query, queryArray, (err, result) => {
    if (err) res.json({ mes: err.message, error: err, result: result });
    else res.json({ mes: "Worker assigned", result: result });
  });
}

async function dropAssignment(req, res) {
  let { assignment_id } = req.body;

  let query = "SELECT * FROM assignments WHERE id = ?";
  let queryArray = [assignment_id];

  const [rows, fields] = await connPromise.execute(query, queryArray);

  const assignment = rows[0];

  console.log(assignment);

  query = "UPDATE assignments SET worker_id = null WHERE id = ?";
  conn.execute(query, queryArray, (err, result) => {
    if (err) res.json({ mes: err.message, error: err, result: result });
    res.json({ mes: "Worker deassigned", result: result });
  });
}

function completeAssignment(req, res) {
  const { assignment_id, final_time, final_cost } = req.body;
  const queryArray = [assignment_id, final_time, final_cost];

  const query = `UPDATE assignments 
    SET completed = TRUE, final_time = ?, final_cost = ? WHERE id = ?`;

  conn.execute(query, queryArray, (err, result) => {
    if (err) res.json({ mes: err.message, error: err, result: result });
    else res.json({ mes: "Assignment Completed", result: result });
  });
}

function uncompleteAssignment(req, res) {
  const query = `UPDATE assignments 
    SET  completed = FALSE,
    final_time = null,
    final_cost = null,
    WHERE id = ?`;

  conn.execute(query, [req.bodyassignment_id], (err, result) => {
    if (err) res.json({ mes: err.message, error: err, result: result });
    else res.json({ mes: "Assignment Completed", result: result });
  });
}

async function checkEmail(email) {
  let query = "SELECT * FROM users WHERE email = ?";
  let queryArray = [email];

  let [rows, fields] = await connPromise.execute(query, queryArray);
  return rows;
}
