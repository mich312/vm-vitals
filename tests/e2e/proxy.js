// Minimal TLS terminator: https://localhost:8443 -> http://127.0.0.1:9110
const https=require('https'), http=require('http'), fs=require('fs');
https.createServer({key:fs.readFileSync((process.env.CERT_DIR||__dirname)+'/key.pem'),cert:fs.readFileSync((process.env.CERT_DIR||__dirname)+'/cert.pem')},(req,res)=>{
  const up=http.request({host:'127.0.0.1',port:9110,path:req.url,method:req.method,headers:req.headers},u=>{
    res.writeHead(u.statusCode,u.headers); u.pipe(res);
  });
  up.on('error',e=>{res.writeHead(502);res.end('upstream: '+e.message);});
  req.pipe(up);
}).listen(8443,()=>console.log('tls proxy on 8443'));
