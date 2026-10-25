
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const allowedOrigins = (process.env.CLIENT_ORIGIN || "http://localhost:5173")
  .split(",").map(origin => origin.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by CORS"));
  }
}));
app.use(express.json({ limit: "1mb" }));

// Ensure the database is connected before each request (safe for serverless cold starts).
app.use(async (req, res, next) => {
  try {
    await connectDatabase();
    next();
  } catch (err) {
    console.error("Database connection failed:", err.message);
    res.status(503).json({ message: "Database connection failed. Check backend environment variables." });
  }
});


const { Schema } = mongoose;

const User = mongoose.model("User", new Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true, lowercase: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["Admin", "HR", "Employee"], required: true },
  employeeId: { type: Schema.Types.ObjectId, ref: "Employee", default: null },
  active: { type: Boolean, default: true },
  mustChangePassword: { type: Boolean, default: false }
}, { timestamps: true }));

const Employee = mongoose.model("Employee", new Schema({
  employeeCode: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true, lowercase: true },
  phone: String,
  address: String,
  department: { type: String, default: "General" },
  designation: { type: String, default: "Employee" },
  basicSalary: { type: Number, min: 1, required: true },
  joinDate: { type: Date, default: Date.now },
  active: { type: Boolean, default: true },
  userId: { type: Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true }));

const Attendance = mongoose.model("Attendance", new Schema({
  employee: { type: Schema.Types.ObjectId, ref: "Employee", required: true },
  dateKey: { type: String, required: true },
  checkIn: Date,
  checkOut: Date,
  status: {
    type: String,
    enum: ["present", "late", "half_day", "absent", "missing_checkout"],
    default: "present"
  }
}, { timestamps: true }));

Attendance.schema.index({ employee: 1, dateKey: 1 }, { unique: true });

const Leave = mongoose.model("Leave", new Schema({
  employee: { type: Schema.Types.ObjectId, ref: "Employee", required: true },
  type: { type: String, enum: ["casual", "sick", "annual", "unpaid"], required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ["pending", "approved", "rejected", "cancelled"], default: "pending" },
  reviewer: { type: Schema.Types.ObjectId, ref: "User" },
  reviewComment: String
}, { timestamps: true }));

const Payroll = mongoose.model("Payroll", new Schema({
  month: { type: String, required: true },
  employee: { type: Schema.Types.ObjectId, ref: "Employee", required: true },
  basic: Number,
  gross: Number,
  deductions: Number,
  net: Number,
  status: { type: String, enum: ["draft", "finalized"], default: "draft" },
  finalizedAt: Date
}, { timestamps: true }));

Payroll.schema.index({ month: 1, employee: 1 }, { unique: true });

const Setting = mongoose.model("Setting", new Schema({
  companyName: { type: String, default: "My Company" },
  officeStart: { type: String, default: "09:00" },
  graceMinutes: { type: Number, default: 15 },
  weekend: { type: [Number], default: [0, 6] },
  leaveQuotas: {
    type: Object,
    default: { casual: 10, sick: 8, annual: 14, unpaid: 999 }
  }
}, { timestamps: true }));

const Audit = mongoose.model("Audit", new Schema({
  actor: { type: Schema.Types.ObjectId, ref: "User" },
  actorName: String,
  action: String,
  entity: String,
  entityId: String,
  details: Schema.Types.Mixed
}, { timestamps: true }));

function tokenFor(user) {
  return jwt.sign({
    id: user._id.toString(),
    role: user.role,
    name: user.name,
    employeeId: user.employeeId?.toString() || null
  }, process.env.JWT_SECRET, { expiresIn: "12h" });
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ message: "Please sign in." });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Session expired. Please sign in again." });
  }
}

const allow = (...roles) => (req, res, next) =>
  roles.includes(req.user.role)
    ? next()
    : res.status(403).json({ message: "You do not have permission for this action." });

async function audit(req, action, entity, entityId, details = {}) {
  await Audit.create({
    actor: req.user.id,
    actorName: req.user.name || "",
    action,
    entity,
    entityId: String(entityId || ""),
    details
  });
}

async function myEmployee(req) {
  if (req.user.role !== "Employee") return null;
  return Employee.findOne({ userId: req.user.id });
}

function dateKey(d = new Date()) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function publicUser(u) {
  return {
    id: u._id,
    name: u.name,
    email: u.email,
    role: u.role,
    employeeId: u.employeeId,
    mustChangePassword: u.mustChangePassword
  };
}

app.get("/api/health", (_, res) =>
  res.json({ ok: true, service: "HCM Lite API" })
);

app.get("/api/setup/status", async (_, res) => {
  const exists = await User.exists({ role: "Admin" });
  res.json({ setupRequired: !exists });
});

app.post("/api/setup", async (req, res) => {
  try {
    if (await User.exists({ role: "Admin" })) {
      return res.status(409).json({ message: "Setup has already been completed." });
    }

    const { companyName, name, email, password } = req.body;

    if (!companyName?.trim() || !name?.trim() || !email?.trim() || !password || password.length < 8) {
      return res.status(400).json({
        message: "Enter company name, admin name, valid email and password (8+ characters)."
      });
    }

    const user = await User.create({
      name,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: "Admin"
    });

    await Setting.create({ companyName: companyName.trim() });
    res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (e) {
    res.status(400).json({
      message: e.code === 11000 ? "Email is already registered." : e.message
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase().trim();
  const user = await User.findOne({ email, active: true });

  if (!user || !(await bcrypt.compare(req.body.password || "", user.passwordHash))) {
    return res.status(401).json({ message: "Incorrect email or password." });
  }

  res.json({ token: tokenFor(user), user: publicUser(user) });
});

app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user || !user.active) return res.status(401).json({ message: "Account unavailable." });
  res.json({ user: publicUser(user) });
});

app.post("/api/auth/change-password", auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);

  if (!user || !(await bcrypt.compare(currentPassword || "", user.passwordHash))) {
    return res.status(400).json({ message: "Current password is incorrect." });
  }

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ message: "New password must be at least 8 characters." });
  }

  user.passwordHash = await bcrypt.hash(newPassword, 12);
  user.mustChangePassword = false;
  await user.save();

  res.json({ message: "Password updated." });
});

app.get("/api/settings", auth, async (req, res) => {
  if (req.user.role === "Employee") {
    return res.status(403).json({ message: "Admin/HR only." });
  }

  let s = await Setting.findOne();
  if (!s) s = await Setting.create({});
  res.json(s);
});

app.put("/api/settings", auth, allow("Admin"), async (req, res) => {
  const s = await Setting.findOneAndUpdate({}, {
    $set: {
      companyName: req.body.companyName,
      officeStart: req.body.officeStart,
      graceMinutes: Number(req.body.graceMinutes),
      weekend: req.body.weekend
    }
  }, { new: true, upsert: true, runValidators: true });

  await audit(req, "update", "settings", s._id, { companyName: s.companyName });
  res.json(s);
});

app.get("/api/employees", auth, async (req, res) => {
  if (req.user.role === "Employee") {
    const own = await myEmployee(req);
    return res.json(own ? [own] : []);
  }

  const q = {};

  if (req.query.search) {
    q.$or = [
      { name: { $regex: req.query.search, $options: "i" } },
      { email: { $regex: req.query.search, $options: "i" } },
      { employeeCode: { $regex: req.query.search, $options: "i" } }
    ];
  }

  if (req.query.department) q.department = req.query.department;

  res.json(await Employee.find(q).sort({ createdAt: -1 }).limit(500));
});

app.post("/api/employees", auth, allow("Admin", "HR"), async (req, res) => {
  try {
    const {
      employeeCode, name, email, basicSalary,
      department, designation, phone, address, joinDate
    } = req.body;

    if (!employeeCode || !name || !email || !(Number(basicSalary) > 0)) {
      return res.status(400).json({
        message: "Employee code, name, email and positive basic salary are required."
      });
    }

    const temporaryPassword = Math.random().toString(36).slice(-8) + "A9!";

    const employee = await Employee.create({
      employeeCode, name, email,
      basicSalary: Number(basicSalary),
      department, designation, phone, address,
      joinDate: joinDate || new Date()
    });

    let user;
    try {
      user = await User.create({
        name,
        email,
        passwordHash: await bcrypt.hash(temporaryPassword, 12),
        role: "Employee",
        employeeId: employee._id,
        mustChangePassword: true
      });
      employee.userId = user._id;
      await employee.save();
    } catch (createError) {
      await Employee.findByIdAndDelete(employee._id).catch(() => {});
      if (user?._id) await User.findByIdAndDelete(user._id).catch(() => {});
      throw createError;
    }

    await audit(req, "create", "employee", employee._id, { employeeCode, email });
    res.status(201).json({ employee, temporaryPassword });
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({ message: "Employee code or email already exists." });
    }
    res.status(400).json({ message: e.message });
  }
});

app.put("/api/employees/:id", auth, allow("HR"), async (req, res) => {
  const allowed = ["name", "phone", "address", "department", "designation", "basicSalary", "active"];
  const update = {};

  allowed.forEach(k => {
    if (req.body[k] !== undefined) update[k] = req.body[k];
  });

  if (update.basicSalary !== undefined && Number(update.basicSalary) <= 0) {
    return res.status(400).json({ message: "Salary must be positive." });
  }

  const e = await Employee.findByIdAndUpdate(req.params.id, update, {
    new: true,
    runValidators: true
  });

  if (!e) return res.status(404).json({ message: "Employee not found." });

  await audit(req, "update", "employee", e._id, update);
  res.json(e);
});

app.delete("/api/employees/:id", auth, allow("Admin", "HR"), async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: "Invalid employee ID." });
  }

  const employee = await Employee.findById(req.params.id);
  if (!employee) return res.status(404).json({ message: "Employee not found." });

  try {
    // Remove related records to avoid orphaned HR data.
    await Promise.all([
      User.deleteMany({ $or: [{ employeeId: employee._id }, ...(employee.userId ? [{ _id: employee.userId }] : [])] }),
      Attendance.deleteMany({ employee: employee._id }),
      Leave.deleteMany({ employee: employee._id }),
      Payroll.deleteMany({ employee: employee._id })
    ]);
    await Employee.findByIdAndDelete(employee._id);
    await audit(req, "delete", "employee", employee._id, {
      employeeCode: employee.employeeCode,
      email: employee.email,
      name: employee.name
    });
    res.json({ message: "Employee and related records deleted." });
  } catch (error) {
    console.error("Employee deletion error:", error);
    res.status(500).json({ message: "Could not delete employee." });
  }
});

/* EMPLOYEE SELF CHECK-IN */
app.post("/api/attendance/check-in", auth, allow("Employee"), async (req, res) => {
  const employee = await myEmployee(req);

  if (!employee) {
    return res.status(404).json({ message: "Employee profile not found." });
  }

  const key = dateKey();

  try {
    const now = new Date();
    const settings = await Setting.findOne();
    const [h, m] = (settings?.officeStart || "09:00").split(":").map(Number);

    const cutoff = new Date(now);
    cutoff.setHours(h, m + Number(settings?.graceMinutes ?? 15), 0, 0);

    const status = now > cutoff ? "late" : "present";

    const record = await Attendance.create({
      employee: employee._id,
      dateKey: key,
      checkIn: now,
      status
    });

    await audit(req, "check-in", "attendance", record._id);
    res.status(201).json(record);
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({ message: "You already have an attendance record today." });
    }
    console.error("Check-in error:", e);
    res.status(500).json({ message: "Could not check in." });
  }
});

/* EMPLOYEE SELF CHECK-OUT */
app.post("/api/attendance/check-out", auth, allow("Employee"), async (req, res) => {
  const employee = await myEmployee(req);

  if (!employee) {
    return res.status(404).json({ message: "Employee profile not found." });
  }

  const record = await Attendance.findOne({
    employee: employee._id,
    dateKey: dateKey()
  });

  if (!record) return res.status(400).json({ message: "Check in first." });
  if (record.checkOut) return res.status(409).json({ message: "You already checked out." });

  record.checkOut = new Date();

  if (record.checkIn) {
    const hours = (record.checkOut - record.checkIn) / 3600000;
    if (hours < 5) record.status = "half_day";
  }

  await record.save();
  await audit(req, "check-out", "attendance", record._id);
  res.json(record);
});

/* ADMIN / HR MANUAL ATTENDANCE: PRESENT OR ABSENT */
app.post("/api/attendance/mark", auth, allow("Admin", "HR"), async (req, res) => {
  try {
    const { employeeId, dateKey: selectedDate, status } = req.body;

    if (!mongoose.isValidObjectId(employeeId)) {
      return res.status(400).json({ message: "Select a valid employee." });
    }

    if (!selectedDate || !/^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) {
      return res.status(400).json({ message: "Select a valid date." });
    }

    const parsedDate = new Date(`${selectedDate}T00:00:00Z`);

    if (
      Number.isNaN(parsedDate.getTime()) ||
      parsedDate.toISOString().slice(0, 10) !== selectedDate
    ) {
      return res.status(400).json({ message: "Invalid attendance date." });
    }

    if (!["present", "absent"].includes(status)) {
      return res.status(400).json({ message: "Status must be present or absent." });
    }

    const employee = await Employee.findById(employeeId);

    if (!employee) {
      return res.status(404).json({ message: "Employee not found." });
    }

    // Update an existing record instead of creating duplicates.
    // Existing check-in/check-out times are preserved.
    const record = await Attendance.findOneAndUpdate(
      { employee: employeeId, dateKey: selectedDate },
      { $set: { status } },
      {
        new: true,
        upsert: true,
        runValidators: true,
        setDefaultsOnInsert: true
      }
    );

    await audit(req, "mark-attendance", "attendance", record._id, {
      employee: employee.name,
      dateKey: selectedDate,
      status
    });

    const populated = await Attendance.findById(record._id)
      .populate("employee", "name employeeCode department");

    res.json(populated);
  } catch (error) {
    console.error("Attendance marking error:", error);

    if (error.code === 11000) {
      return res.status(409).json({
        message: "Attendance record already exists. Refresh and try again."
      });
    }

    res.status(500).json({ message: "Could not save attendance." });
  }
});

app.get("/api/attendance", auth, async (req, res) => {
  const q = {};

  if (req.user.role === "Employee") {
    const e = await myEmployee(req);
    if (!e) return res.json([]);
    q.employee = e._id;
  }

  if (req.query.month) {
    if (!/^\d{4}-\d{2}$/.test(req.query.month)) {
      return res.status(400).json({ message: "Month must be YYYY-MM." });
    }
    q.dateKey = { $regex: `^${req.query.month}` };
  }

  res.json(
    await Attendance.find(q)
      .populate("employee", "name employeeCode department")
      .sort({ dateKey: -1 })
      .limit(500)
  );
});

app.post("/api/leaves", auth, allow("Employee"), async (req, res) => {
  const employee = await myEmployee(req);

  if (!employee) {
    return res.status(404).json({ message: "Employee profile not found." });
  }

  const { type, startDate, endDate, reason } = req.body;
  const start = new Date(startDate);
  const end = new Date(endDate);

  if (
    !["casual", "sick", "annual", "unpaid"].includes(type) ||
    !startDate || !endDate ||
    isNaN(start) || isNaN(end) ||
    start > end || !reason?.trim()
  ) {
    return res.status(400).json({
      message: "Enter a valid leave type, date range and reason."
    });
  }

  const overlap = await Leave.findOne({
    employee: employee._id,
    status: { $in: ["pending", "approved"] },
    startDate: { $lte: end },
    endDate: { $gte: start }
  });

  if (overlap) {
    return res.status(422).json({
      message: "This request overlaps another pending or approved leave."
    });
  }

  const leave = await Leave.create({ employee: employee._id, type, startDate: start, endDate: end, reason });
  await audit(req, "create", "leave", leave._id);
  res.status(201).json(leave);
});

app.get("/api/leaves", auth, async (req, res) => {
  const q = {};

  if (req.user.role === "Employee") {
    const e = await myEmployee(req);
    if (!e) return res.json([]);
    q.employee = e._id;
  }

  if (req.query.status) q.status = req.query.status;

  res.json(
    await Leave.find(q)
      .populate("employee", "name employeeCode department")
      .sort({ createdAt: -1 })
      .limit(500)
  );
});

app.patch("/api/leaves/:id/review", auth, allow("Admin", "HR"), async (req, res) => {
  if (!["approved", "rejected"].includes(req.body.status)) {
    return res.status(400).json({ message: "Status must be approved or rejected." });
  }

  const leave = await Leave.findById(req.params.id);
  if (!leave) return res.status(404).json({ message: "Leave request not found." });

  if (leave.status !== "pending") {
    return res.status(409).json({ message: "Only pending requests can be reviewed." });
  }

  leave.status = req.body.status;
  leave.reviewer = req.user.id;
  leave.reviewComment = String(req.body.comment || "").slice(0, 500);

  await leave.save();
  await audit(req, req.body.status, "leave", leave._id);
  res.json(leave);
});

app.post("/api/payroll/run", auth, allow("HR"), async (req, res) => {
  const month = String(req.body.month || "");

  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ message: "Month must be YYYY-MM." });
  }

  const employees = await Employee.find({ active: true });
  const days = new Date(Number(month.slice(0, 4)), Number(month.slice(5, 7)), 0).getDate();
  const results = [];

  for (const e of employees) {
    const existing = await Payroll.findOne({ month, employee: e._id });

    if (existing?.status === "finalized") {
      results.push(existing);
      continue;
    }

    const gross = Math.round(Number(e.basicSalary) * 1.5);
    const records = await Attendance.find({
      employee: e._id,
      dateKey: { $regex: `^${month}` }
    });

    const absent = Math.max(0, days - records.length);
    const halfDays = records.filter(r => r.status === "half_day").length;

    const unpaid = await Leave.find({
      employee: e._id,
      type: "unpaid",
      status: "approved",
      startDate: { $lte: new Date(`${month}-31T23:59:59`) },
      endDate: { $gte: new Date(`${month}-01T00:00:00`) }
    });

    const unpaidDays = unpaid.reduce(
      (n, l) => n + Math.max(1, Math.round((new Date(l.endDate) - new Date(l.startDate)) / 86400000) + 1),
      0
    );

    const perDay = gross / Math.max(days, 1);
    const deductions = Math.round(perDay * (absent + halfDays * 0.5 + unpaidDays));

    const data = {
      month,
      employee: e._id,
      basic: e.basicSalary,
      gross,
      deductions,
      net: Math.max(0, gross - deductions),
      status: "draft"
    };

    const row = existing
      ? await Payroll.findByIdAndUpdate(existing._id, data, { new: true })
      : await Payroll.create(data);

    results.push(row);
  }

  await audit(req, "run", "payroll", month, { count: results.length });

  res.json({
    month,
    count: results.length,
    payroll: await Payroll.find({ month })
      .populate("employee", "name employeeCode department")
      .sort({ createdAt: -1 })
  });
});

app.get("/api/payroll", auth, async (req, res) => {
  const q = {};

  if (req.query.month) q.month = req.query.month;

  if (req.user.role === "Employee") {
    const e = await myEmployee(req);
    if (!e) return res.json([]);
    q.employee = e._id;
  }

  res.json(
    await Payroll.find(q)
      .populate("employee", "name employeeCode department")
      .sort({ month: -1 })
      .limit(500)
  );
});

app.post("/api/payroll/:month/finalize", auth, allow("Admin"), async (req, res) => {
  const rows = await Payroll.find({ month: req.params.month });

  if (!rows.length) {
    return res.status(404).json({ message: "Run payroll before finalizing." });
  }

  await Payroll.updateMany(
    { month: req.params.month, status: "draft" },
    { $set: { status: "finalized", finalizedAt: new Date() } }
  );

  await audit(req, "finalize", "payroll", req.params.month, { count: rows.length });
  res.json({ message: "Payroll finalized and locked.", count: rows.length });
});

app.get("/api/dashboard", auth, async (req, res) => {
  const own = req.user.role === "Employee" ? await myEmployee(req) : null;
  const employeeFilter = own ? { employee: own._id } : {};

  const [
    employeeCount, today, pendingLeaves, leaves,
    payroll, attendance, recentAudit, setting
  ] = await Promise.all([
    own ? Promise.resolve(1) : Employee.countDocuments({ active: true }),
    Attendance.find({ ...employeeFilter, dateKey: dateKey() }).populate("employee", "name department"),
    Leave.countDocuments({ ...employeeFilter, status: "pending" }),
    Leave.find(employeeFilter).populate("employee", "name department").sort({ createdAt: -1 }).limit(100),
    Payroll.find(employeeFilter).populate("employee", "name department").sort({ month: -1 }).limit(100),
    Attendance.find(employeeFilter).populate("employee", "name department").sort({ dateKey: -1 }).limit(100),
    req.user.role === "Admin" ? Audit.find().sort({ createdAt: -1 }).limit(10) : Promise.resolve([]),
    Setting.findOne()
  ]);

  const lateToday = today.filter(x => x.status === "late").length;

  const onLeaveToday = leaves.filter(l =>
    l.status === "approved" &&
    new Date(l.startDate) <= new Date() &&
    new Date(l.endDate) >= new Date()
  ).length;

  res.json({
    companyName: setting?.companyName || "HCM Lite",
    employeeCount,
    presentToday: today.length,
    lateToday,
    onLeaveToday,
    pendingLeaves,
    attendance: attendance.slice(0, 10),
    leaves,
    payroll,
    audit: recentAudit
  });
});

app.get("/api/audit", auth, allow("Admin"), async (_, res) => {
  res.json(await Audit.find().sort({ createdAt: -1 }).limit(200));
});

/* AI ASSISTANT */
app.post("/api/ai/chat", auth, async (req, res) => {
  const question = String(req.body.message || "").trim();

  if (!question) {
    return res.status(400).json({ message: "Type a question first." });
  }

  try {
    const own = req.user.role === "Employee" ? await myEmployee(req) : null;
    const filter = own ? { employee: own._id } : {};

    const [employeeCount, attendance, leaves, payroll, settings] = await Promise.all([
      own ? Promise.resolve(1) : Employee.countDocuments({ active: true }),
      Attendance.find(filter).populate("employee", "name department").sort({ dateKey: -1 }).limit(100),
      Leave.find(filter).populate("employee", "name department").sort({ createdAt: -1 }).limit(100),
      Payroll.find(filter).populate("employee", "name department").sort({ month: -1 }).limit(50),
      Setting.findOne()
    ]);

    const safeContext = {
      role: req.user.role,
      company: settings?.companyName || "HCM Lite",
      activeEmployees: employeeCount,
      attendance: attendance.map(a => ({
        employee: a.employee?.name,
        date: a.dateKey,
        status: a.status
      })),
      leaves: leaves.map(l => ({
        employee: l.employee?.name,
        type: l.type,
        start: l.startDate,
        end: l.endDate,
        status: l.status,
        reason: l.reason
      })),
      payroll: payroll.map(p => ({
        employee: p.employee?.name,
        month: p.month,
        gross: p.gross,
        net: p.net,
        status: p.status
      }))
    };

    if (!process.env.GEMINI_API_KEY) {
      const answer = /leave/i.test(question)
        ? `I can see ${leaves.filter(l => l.status === "approved").length} approved leave request(s) in the records I checked.`
        : /late/i.test(question)
        ? `There are ${attendance.filter(a => a.status === "late").length} late attendance record(s) in the recent records I checked.`
        : /employee|headcount|staff/i.test(question)
        ? `There are ${employeeCount} active employee(s) visible to your role.`
        : "AI is not configured yet. Add GEMINI_API_KEY to the server .env file. I can answer basic employee, leave and late-count questions from the available records.";

      return res.json({ answer, aiGenerated: false });
    }

    const prompt = `You are HCM Lite's HR assistant. Answer only from the JSON data and stated rules. Never reveal salary or private details to an Employee. If the data does not answer the question, say so. Rules: office starts 09:00 with 15 minute grace; casual leave quota 10, sick 8, annual 14; HR approves leave; only Admin finalizes payroll. User role: ${req.user.role}. Data JSON: ${JSON.stringify(safeContext)}. Question: ${question}`;

    const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error?.message || "AI provider error");
    }

    res.json({
      answer: data.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("") || "I could not generate an answer.",
      aiGenerated: true
    });
  } catch (error) {
    console.error("AI chat error:", error);
    res.status(500).json({ message: "AI assistant request failed." });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Unexpected server error." });
});


async function connectDatabase() {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is required in environment variables");
  }
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is required in environment variables");
  }
  if (mongoose.connection.readyState === 1) return;
  if (!global.__hcmMongoConnectPromise) {
    global.__hcmMongoConnectPromise = mongoose.connect(process.env.MONGODB_URI)
      .then(async () => {
        if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD &&
            !(await User.exists({ role: "Admin" }))) {
          const user = await User.create({
            name: "System Admin",
            email: process.env.ADMIN_EMAIL.toLowerCase(),
            passwordHash: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12),
            role: "Admin"
          });
          console.log(`Initial Admin created: ${user.email}`);
        }
      })
      .catch(err => {
        global.__hcmMongoConnectPromise = null;
        throw err;
      });
  }
  await global.__hcmMongoConnectPromise;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 5000);
  connectDatabase()
    .then(() => app.listen(port, () => console.log(`HCM Lite API running on http://localhost:${port}`)))
    .catch(err => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = app;
