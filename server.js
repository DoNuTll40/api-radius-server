const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const prisma = require('./config/prisma');
const bcrypt = require('bcrypt');
const db_b = require('./config/db_b');
require("dotenv").config();

const app = express();

const port = process.env.PORT;

app.use(cors({
  origin: '*',
}));
app.use(express.json());
app.use(morgan('dev'));

const fortigate = "/api/fortigate";

// ตรวจสอบเลขบัตรประจำตัวประชาชน
function isThaiCitizenId(national_id) {
  if (!/^\d{13}$/.test(national_id)) return false;
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(national_id[i]) * (13 - i);
  const checkDigit = (11 - (sum % 11)) % 10;
  return checkDigit === Number(national_id[12]);
};

// ตรวจสอบว่า Password ที่ส่ง Request มามีตัวเลขตัวอักขระพิเศษหรือตัวอักษรภาษาอังกฤษหรือไม่
function validatePassword(password) {
  const minLength = 8;

  // อย่างน้อย 1 ตัวอักษร A–Z หรือ a–z
  const hasLetter = /[a-z]/.test(password);

  // อย่างน้อย 1 ตัวเลข 0–9
  const hasNumber = /\d/.test(password);

  // อย่างน้อย 1 ตัวอักขระพิเศษ (ปรับชุดตามต้องการ)
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return password.length >= minLength && hasLetter && hasNumber && hasSpecial;
};

// Hash Password
async function hashPassword(plainPassword) {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(plainPassword, salt);
  return hashedPassword;
};

// Register
app.post(`${fortigate}/register`, async (req, res, next) => {
  try {
    // Set ค่าตัวแปรของข้อมูลที่ล็อคไว้สำหรับบันทึกให้ User
    const rad = {
      checkAttribute: "Cleartext-Password",
      checkOp: ":=", // ค่าเปรียบเที่ยบ
      replyAttribute: "Session-Timeout", // หมดเวลาการใช้งาน
      replyOp: ":=", // ค่าเปรียบเที่ยบ
      replyValue: "14400" // 4 ชั่วโมง
    };

    // รับค่าจาก request ที่ส่งเข้ามา
    const userData = req.body;
    // ตรวจสอบว่ามีการส่งข้อมูลมาจริงหรือไม่?
    if(!userData) return res.status(400).json({ code: 400, status: "error", message: `กรุณากรอกข้อมูลให้ครบถ้วน!` });

    // ตรวจสอบว่า Username ที่ส่งมาอยู่ในรูปแบบของเลขบัตรประจำตัวประชาชนหรือไม่?
    const checkUsernameInNationalId = await isThaiCitizenId(userData.username);
    if (!checkUsernameInNationalId) return res.status(400).json({ code: 400, status: "error", message: `${userData.username} ต้องเป็นเลขบัตรประจำตัวประชาชนเท่านั้น!` });

    // ตรวจสอบว่า username ที่ส่งมามีข้อมูลอยู่ในระบบ BackOffice จริงหรือไม่ เพราะถ้าเป็นเจ้าหน้าที่ต้องมีข้อมูลใน BackOffice
    const [rows] = await db_b.query('SELECT ID FROM hrd_person WHERE HR_CID = ? LIMIT 1', [userData.username]);
    if (rows.length === 0) return res.status(400).json({ code: 400, status: "error", message: `ไม่สามารถ Register ได้เนื่องจากท่านไม่ใช่เจ้าหน้าที่ภายในโรงพยาบาล!` });

    // ตรวจสอบว่ามี Username ซ้ำหรือไม่ในระบบ
    const checkUniqueUsername = await prisma.radcheck.findFirst({ where: { username: userData.username }, select: { id: true } });
    if (checkUniqueUsername) return res.status(409).json({ code: 409, status: "error", message: `มีข้อมูล ${userData.username} อยู่ในระบบแล้วไม่สามารถใช้งานซ้ำได้!` });

    // Validate ของ Password
    const checkValidatePassword = await validatePassword(userData.password);
    if (!checkValidatePassword) return res.status(409).json({ code: 409, status: "error", message: `รหัสผ่านควรประกอบไปด้วยตัวเลขตัวอักขระพิเศษตัวภาษาอังกฤษรวมกันอย่างน้อย 8 ตัว!` });

    // เรียกใช้งาน Function สำหรับ hash password
    const password = await hashPassword(userData.password);

    // สร้าง Payload ของ radcheck เพื่อเตรียมบันทึกข้อมูล
    const radcheckPayload = {
      username: userData.username,
      attribute: rad.checkAttribute,
      op: rad.checkOp,
      value: password
    }

    // บันทึกข้อมูลด้วย payload ที่เตรียมไว้ไปยัง Database
    const createDataRadcheck = await prisma.radcheck.create({ data: { ...radcheckPayload } });
    if (createDataRadcheck) {
      // สร้าง Payload ของ radreply เพื่อเตรียมบันทึกข้อมูล
      const radreplyPayload = {
        username: userData.username,
        attribute: rad.replyAttribute,
        op: rad.replyOp,
        value: rad.replyValue
      }

      // บันทึกข้อมูลด้วย payload ที่เตรียมไว้ไปยัง Database
      const createDataRadreply = await prisma.radreply.create({ data: { ...radreplyPayload } });
      if (createDataRadreply) return res.status(200).json({
        code: 200,
        status: 'success',
        message: 'Create user successfully!'
      });
    }
  } catch (next) {
    console.log(next)
    return res.status(500).json({ code: 500, status: "internal server", message: "" });
  }
});

// Check ข้อมูลก่อนทำการ Login
app.post(`${fortigate}/check`, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ code: 400, status: "error", message: "ไม่พบข้อมูล" });

    const checkUsername = await prisma.radcheck.findFirst({
      where: { username, },
      select: { username: true, value: true }
    });
    if (!checkUsername) return res.status(400).json({ code: 400, status: "error", message: "ไม่พบข้อมูลผู้ใช้งาน" });

    // ตรวจสอบรหัสที่ hash
    const isMatch = await bcrypt.compare(password, checkUsername.value);
    if (!isMatch) return res.status(400).json({ code: 400, status: "error", message: "รหัสผ่านไม่ถูกต้องกรุณาตรวจสอบ!" });

    res.json({ code: 200, status: "success", message: "ตรวจพบข้อมูล" });
  } catch (next) {
    console.log(next)
    return res.status(500).json({ code: 500, status: "internal server", result: checkUsername.value });
  }
});

app.listen(port, () => {
  console.log(`API Server ready: http://localhost:${port}`)
});
