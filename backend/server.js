require('dotenv').config();
const express=require('express');
const mongoose=require('mongoose');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const cors=require('cors');
const app=express();
app.use(cors());
app.use(express.json());

const PORT=process.env.PORT||5000, JWT_SECRET=process.env.JWT_SECRET||'dev-secret-change-me';

const userSchema=new mongoose.Schema({name:{type:String,required:true,trim:true},username:{type:String,required:true,unique:true,lowercase:true,trim:true},password:{type:String,required:true},role:{type:String,enum:['admin','teacher','student'],required:true},studentId:{type:mongoose.Schema.Types.ObjectId,ref:'Student',default:null}},{timestamps:true});
const studentSchema=new mongoose.Schema({name:{type:String,required:true},roll:{type:String,required:true},username:{type:String,required:true,unique:true,lowercase:true},className:{type:String,required:true},section:String,guardian:String,phone:String,dob:String,admission:String});
const teacherSchema=new mongoose.Schema({name:{type:String,required:true},username:{type:String,required:true,unique:true,lowercase:true},subject:{type:String,required:true},phone:String,email:String,joining:String});
const attendanceSchema=new mongoose.Schema({date:{type:String,required:true},studentId:{type:mongoose.Schema.Types.ObjectId,ref:'Student',required:true},status:{type:String,enum:['present','absent','leave'],default:'present'}},{timestamps:true});
attendanceSchema.index({date:1,studentId:1},{unique:true});
const feeSchema=new mongoose.Schema({studentId:{type:mongoose.Schema.Types.ObjectId,ref:'Student',required:true},total:{type:Number,default:0},paid:{type:Number,default:0},date:String,note:String},{timestamps:true});
const settingSchema=new mongoose.Schema({key:{type:String,unique:true},schoolName:String,location:String});
const User=mongoose.model('User',userSchema),Student=mongoose.model('Student',studentSchema),Teacher=mongoose.model('Teacher',teacherSchema),Attendance=mongoose.model('Attendance',attendanceSchema),Fee=mongoose.model('Fee',feeSchema),Setting=mongoose.model('Setting',settingSchema);

function sign(u){return jwt.sign({id:u._id,role:u.role,username:u.username},JWT_SECRET,{expiresIn:'7d'})}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Login required'});req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch(e){res.status(401).json({error:'Invalid or expired session'})}}
const roles=(...rs)=>(req,res,next)=>rs.includes(req.user.role)?next():res.status(403).json({error:'Permission denied'});
const safe=u=>({id:u._id,name:u.name,username:u.username,role:u.role,studentId:u.studentId});

app.post('/api/admin/signup',async(req,res)=>{try{if(await User.exists({role:'admin'}))return res.status(409).json({error:'Admin signup is already closed.'});const {name,username,password}=req.body;if(!name||!username||!password)return res.status(400).json({error:'Name, username and password are required'});const u=await User.create({name,username,password:await bcrypt.hash(password,12),role:'admin'});res.json({token:sign(u),user:safe(u)})}catch(e){res.status(400).json({error:e.code===11000?'Username already exists':e.message})}});
app.post('/api/login',async(req,res)=>{try{const {role,username,password}=req.body;const u=await User.findOne({username:String(username||'').toLowerCase(),role});if(!u||!(await bcrypt.compare(password||'',u.password)))return res.status(401).json({error:'Invalid username or password'});res.json({token:sign(u),user:safe(u)})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/dashboard',auth,roles('admin','teacher','student'),async(req,res)=>{try{const [students,teachers]=await Promise.all([Student.countDocuments(),Teacher.countDocuments()]);const date=new Date().toISOString().slice(0,10);const at=await Attendance.find({date});const present=at.filter(x=>x.status==='present').length,absent=at.filter(x=>x.status==='absent').length,leave=at.filter(x=>x.status==='leave').length;const fees=await Fee.find();const feePaid=fees.reduce((s,x)=>s+x.paid,0),feeDue=fees.reduce((s,x)=>s+Math.max(0,x.total-x.paid),0);res.json({students,teachers,present,absent,leave,feePaid,feeDue})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/students',auth,async(req,res)=>res.json(await Student.find().sort({name:1})));
app.post('/api/students',auth,roles('admin'),async(req,res)=>{try{const {name,roll,username,password,className,section,guardian,phone,dob,admission}=req.body;if(!name||!roll||!username||!password||!className)return res.status(400).json({error:'Required student fields are missing'});const s=await Student.create({name,roll,username:username.toLowerCase(),className,section,guardian,phone,dob,admission});await User.create({name,username:username.toLowerCase(),password:await bcrypt.hash(password,12),role:'student',studentId:s._id});res.status(201).json(s)}catch(e){res.status(400).json({error:e.code===11000?'Username already exists':'Could not create student: '+e.message})}});
app.put('/api/students/:id',auth,roles('admin'),async(req,res)=>{try{const s=await Student.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});if(!s)return res.status(404).json({error:'Student not found'});const u=await User.findOne({studentId:s._id});if(u){u.name=s.name;u.username=s.username.toLowerCase();if(req.body.password)u.password=await bcrypt.hash(req.body.password,12);await u.save()}res.json(s)}catch(e){res.status(400).json({error:e.code===11000?'Username already exists':e.message})}});
app.delete('/api/students/:id',auth,roles('admin'),async(req,res)=>{try{const id=req.params.id;await User.deleteOne({studentId:id});await Attendance.deleteMany({studentId:id});await Fee.deleteMany({studentId:id});await Student.findByIdAndDelete(id);res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/teachers',auth,async(req,res)=>res.json(await Teacher.find().sort({name:1})));
app.post('/api/teachers',auth,roles('admin'),async(req,res)=>{try{const {name,username,password,subject,phone,email,joining}=req.body;if(!name||!username||!password||!subject)return res.status(400).json({error:'Required teacher fields are missing'});const t=await Teacher.create({name,username:username.toLowerCase(),subject,phone,email,joining});try{await User.create({name,username:username.toLowerCase(),password:await bcrypt.hash(password,12),role:'teacher'})}catch(e){await Teacher.findByIdAndDelete(t._id);throw e}res.status(201).json(t)}catch(e){res.status(400).json({error:e.code===11000?'Username already exists':e.message})}});
app.put('/api/teachers/:id',auth,roles('admin'),async(req,res)=>{try{const t=await Teacher.findByIdAndUpdate(req.params.id,req.body,{new:true,runValidators:true});if(!t)return res.status(404).json({error:'Teacher not found'});const u=await User.findOne({username:req.body.oldUsername||t.username,role:'teacher'});const u2=u||await User.findOne({username:t.username,role:'teacher'});if(u2){u2.name=t.name;u2.username=t.username.toLowerCase();if(req.body.password)u2.password=await bcrypt.hash(req.body.password,12);await u2.save()}res.json(t)}catch(e){res.status(400).json({error:e.code===11000?'Username already exists':e.message})}});
app.delete('/api/teachers/:id',auth,roles('admin'),async(req,res)=>{try{const t=await Teacher.findById(req.params.id);if(t)await User.deleteOne({username:t.username,role:'teacher'});await Teacher.findByIdAndDelete(req.params.id);res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/attendance',auth,async(req,res)=>{const rows=await Attendance.find({date:req.query.date||new Date().toISOString().slice(0,10)}).populate('studentId');res.json(rows)});
app.post('/api/attendance/bulk',auth,roles('admin','teacher'),async(req,res)=>{try{const date=req.body.date||new Date().toISOString().slice(0,10),records=req.body.records||{};for(const [studentId,status] of Object.entries(records))await Attendance.findOneAndUpdate({date,studentId},{date,studentId,status},{upsert:true,new:true,setDefaultsOnInsert:true});res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/fees',auth,async(req,res)=>res.json(await Fee.find().populate('studentId').sort({updatedAt:-1})));
app.post('/api/fees',auth,roles('admin','teacher'),async(req,res)=>{try{const {studentId,total,paid,date,note}=req.body;const f=await Fee.findOneAndUpdate({studentId},{studentId,total:Number(total)||0,paid:Number(paid)||0,date,note},{upsert:true,new:true,setDefaultsOnInsert:true});res.json(f)}catch(e){res.status(400).json({error:e.message})}});

app.get('/api/reports',auth,async(req,res)=>{const students=await Student.find();const date=new Date().toISOString().slice(0,10);const at=await Attendance.find({date});const by={};students.forEach(s=>{by[s.className]??={students:0,present:0};by[s.className].students++});at.forEach(a=>{const s=students.find(x=>String(x._id)===String(a.studentId));if(s&&a.status==='present')by[s.className].present++});res.json(Object.entries(by).map(([className,x])=>({className,...x,rate:x.students?Math.round(x.present/x.students*100):0})))});
app.get('/api/settings',auth,async(req,res)=>{const x=await Setting.findOne({key:'school'});res.json(x||{schoolName:'Naitik Public School',location:'Birja'})});
app.put('/api/settings',auth,roles('admin'),async(req,res)=>{const x=await Setting.findOneAndUpdate({key:'school'},{key:'school',schoolName:req.body.schoolName||'Naitik Public School',location:req.body.location||'Birja'},{upsert:true,new:true});res.json(x)});


mongoose.connect(
  process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/naitik_public_school'
)
.then(() => {
  console.log('MongoDB connected successfully');
  app.listen(PORT, () => {
    console.log(`Naitik Public School running: http://localhost:${PORT}`);
  });
})
.catch(e => {
  console.error('MongoDB connection failed:', e.message);
  process.exit(1);
});
