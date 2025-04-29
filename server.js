const express = require('express')
const cors = require('cors')
const morgan = require('morgan');
const prisma = require('./config/prisma');
require("dotenv").config();

const app = express()

const port = process.env.PORT

app.use(cors())
app.use(express.json())
app.use(morgan('dev'))

app.post('/api/fortigate/check', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if(!username || !password) return res.status(400).json({ code: 400, status: "error", message: "ไม่พบข้อมูล"});

    const checkUsername = await prisma.radcheck.findFirst({
      where: {
        username,
      }
    });

    if(!checkUsername) return res.status(400).json({ code: 400, status: "error", message: "ไม่พบข้อมูลผู้ใช้งาน"});
    
    const checkPassword = await prisma.radcheck.findFirst({
      where: {
        AND: [
          { username },
          { value: password},
        ]
      }
    });

    if(!checkPassword) return res.status(400).json({ code: 400, status: "error", message: "รหัสผ่านไม่ถูกต้อง"});

    res.json({ code: 200, status: "success", message: "ตรวจพบข้อมูล"});

  } catch (next) {
    console.log(next)
    return res.status(500).json({ code: 500, status: "internal server", message: "" });
  }
})

app.listen(port, () => {
  console.log(`API Server ready: http://localhost:${port}`)
})
