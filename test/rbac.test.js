const request = require("supertest");
const { expect } = require("chai");
const jwt = require("jsonwebtoken");
const app = require("../src/server.js");


describe("🎓 Newton School RBAC Assignment", () => {
  let adminToken, teacherToken, studentToken;

  const users = [
    { username: "yash", password: "123", role: "admin" },
    { username: "ankit", password: "123", role: "teacher" },
    { username: "anurag", password: "123", role: "student" },
  ];

  // --- LOGIN TESTS ---
  describe("🔐 /login endpoint", () => {
    it("should login admin and return JWT", async () => {
      const res = await request(app).post("/login").send(users[0]);
      expect(res.status).to.equal(200);
      expect(res.body).to.have.property("token");
      adminToken = res.body.token;
      const decoded = jwt.decode(adminToken);
      expect(decoded.role).to.equal("admin");
    });

    it("should login teacher and return JWT", async () => {
      const res = await request(app).post("/login").send(users[1]);
      expect(res.status).to.equal(200);
      teacherToken = res.body.token;
    });

    it("should login student and return JWT", async () => {
      const res = await request(app).post("/login").send(users[2]);
      expect(res.status).to.equal(200);
      studentToken = res.body.token;
    });

    it("should reject invalid credentials", async () => {
      const res = await request(app).post("/login").send({
        username: "alice",
        password: "wrong",
      });
      expect(res.status).to.equal(401);
    });
  });

  // --- PROTECTED ROUTES TESTS ---
  describe("🛡️ Role-based access", () => {
    it("should allow admin to access /admin", async () => {
      const res = await request(app)
        .get("/admin")
        .set("Authorization", `Bearer ${adminToken}`);
      expect(res.status).to.equal(200);
      expect(res.text).to.include("admin");
    });

    it("should deny teacher from accessing /admin", async () => {
      const res = await request(app)
        .get("/admin")
        .set("Authorization", `Bearer ${teacherToken}`);
      expect(res.status).to.equal(403);
    });

    it("should allow teacher to access /teacher", async () => {
      const res = await request(app)
        .get("/teacher")
        .set("Authorization", `Bearer ${teacherToken}`);
      expect(res.status).to.equal(200);
      expect(res.text).to.include("teacher");
    });

    it("should deny student from accessing /teacher", async () => {
      const res = await request(app)
        .get("/teacher")
        .set("Authorization", `Bearer ${studentToken}`);
      expect(res.status).to.equal(403);
    });

    it("should allow student to access /student", async () => {
      const res = await request(app)
        .get("/student")
        .set("Authorization", `Bearer ${studentToken}`);
      expect(res.status).to.equal(200);
      expect(res.text).to.include("student");
    });

    it("should reject access with missing token", async () => {
      const res = await request(app).get("/admin");
      expect(res.status).to.equal(401);
    });

    it("should reject access with invalid token", async () => {
      const res = await request(app)
        .get("/admin")
        .set("Authorization", "Bearer invalid.token.here");
      expect(res.status).to.equal(403);
    });
  });
});
