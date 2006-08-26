/*
 * perl antispam smtp proxy
 * (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>
 *
 * version='1.2.0'
 * modversion=' beta 0'
 *
 */

/*

RSLite - by Brent Ashley
Simple non-concurrent remote scripting calls.
send one string, receive one string

1) use this include
2) in body_onload(), set the RSLite var:
   RSLite = new RSLiteObject();
3) before using, set callback and failure functions if you want more than an alert
4) set interval and attempts for retries if defaults not suitable
5) call it, passing single parm:
   RSLite.call( rsPage, parm )
6) your callback receives string, or failure function called.

rsPage simply takes input parm "p" and sets session-expiry cookie called "RSLite".

04.03.2006 modified by Przemek Czerkas - create image as object property.

*/

function RSLiteObject(){
  this.interval = 100;
  this.attempts = 60;
  this.image = new Image();
  this.call = function ( page, parm ){
    parm = (parm != null)? parm : '';
    var d = new Date();
    document.cookie = 'RSLite=x; expires=Fri, 31 Dec 1999 23:59:59 GMT;';
    this.image.src = page + '?u=' + d.getTime() + '&p=' + parm;
    setTimeout( "RSLite.receive(1);", this.interval );
  }  
  this.receive = function ( attempt ){  
                   var response = null;
                   var aCookie = document.cookie.split("; ");
                   for (var i=0; i < aCookie.length; i++){
                     var aCrumb = aCookie[i].split("=");
                     if (aCrumb[0] == 'RSLite') response = aCrumb[1];
                   }
                   if ( response != null ){
                     this.callback( unescape(response.replace(/\+/g,' ')) );
                   } else {
                     if (attempt < this.attempts){
                       setTimeout( "RSLite.receive( " + (attempt+1) +" );",this.interval);
                     } else {
                       this.failure();
                     }
                   }    
                 }
  this.callback = function( response ){ 
                    alert(response); 
                  }
  this.failure = function(){ 
                   alert( "RSLite timed out"); 
                 }
}
var RSLite;
