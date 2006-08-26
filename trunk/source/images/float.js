/*
 * perl antispam smtp proxy
 * (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>
 *
 * version='1.2.0'
 * modversion=' beta 0'
 *
 */

function docHeight() {
  if (typeof document.height!='undefined') {
    return document.height;
  } else if (document.compatMode && document.compatMode!='BackCompat') {
    return document.documentElement.scrollHeight;
  } else if (document.body && typeof document.body.scrollHeight!='undefined') {
    return document.body.scrollHeight;
  }
}

//********************************************************
//* You may use this code for free on any web page provided that
//* these comment lines and the following credit remain in the code.
//* Floating Div from http://www.javascript-fx.com
//********************************************************
// Modified in May 2005 by Przemek Czerkas:
//  - added calls to docHeight()
//  - added bounding params tlx, tly, brx, bry
var ns=(navigator.appName.indexOf('Netscape')!=-1);
var d=document;
var px=document.layers ? '' : 'px';
function JSFX_FloatDiv(id, sx, sy, tlx, tly, brx, bry) {
  var el=d.getElementById ? d.getElementById(id) : d.all ? d.all[id] : d.layers[id];
  window[id+'_obj']=el;
  if (d.layers) el.style=el;
  el.cx=el.sx=sx;
  el.cy=el.sy=sy;
  el.tlx=tlx;
  el.tly=tly;
  el.brx=brx;
  el.bry=bry;
  el.sP=function(x,y) { this.style.left=x+px;this.style.top=y+px; };
  el.flt=function() {
    var pX, pY;
    pX=ns ? pageXOffset : document.documentElement && document.documentElement.scrollLeft ? document.documentElement.scrollLeft : document.body.scrollLeft;
    pY=ns ? pageYOffset : document.documentElement && document.documentElement.scrollTop ? document.documentElement.scrollTop : document.body.scrollTop;
    if (this.sy<0)
      pY+=ns ? innerHeight : document.documentElement && document.documentElement.clientHeight ? document.documentElement.clientHeight : document.body.clientHeight;
    this.cx+=(pX+Math.max(this.sx-pX, this.tlx)-this.cx)/4;
    this.cy+=(pY+Math.max(this.sy-pY, this.tly)-this.cy)/4;
    this.cx=Math.min(this.cx, this.brx);
    this.cy=Math.min(this.cy, this.bry);
    if (ns) {
      this.sP(
        Math.max(Math.min(this.cx+this.clientWidth,document.width)-this.clientWidth,this.sx),
        Math.max(Math.min(this.cy+this.clientHeight,document.height)-this.clientHeight,this.sy)
      );
    } else {
      var oldh, newh;
      oldh=docHeight();
      this.sP(this.cx, this.cy);
      newh=docHeight();
      if (newh>oldh) {
        this.sP(this.cx, this.cy-(newh-oldh));
      }
    }
    setTimeout(this.id+'_obj.flt()', 20);
  }
  return el;
}
