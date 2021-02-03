module.exports = function (app) {
  
  if(typeof process.env.AUTH_TYPE === 'undefined' || process.env.AUTH_TYPE == "" || process.env.AUTH_TYPE == "none"){
    return;
  }
  
  switch(process.env.AUTH_TYPE){
    case 'simple-form':
      throw new Error("Simple form is not supported yet");
    break;
    default:
      require('./Oauth2')(app);      
  }  
  
}
