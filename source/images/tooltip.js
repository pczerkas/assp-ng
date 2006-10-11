/*
 * perl antispam smtp proxy
 * (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>
 *
 * version='1.2.0'
 * modversion=' beta 0'
 *
 */

tooltip_pop=tooltip_timer=tooltip_elem=null;

function initTooltip(el) {
  el.onmouseover=showTooltip;
  el.onmouseout=hideTooltip;
  if (el.captureEvents) el.captureEvents(Event.MOUSEOVER | Event.MOUSEOUT);
  if (!tooltip_pop) tooltip_pop=document.getElementById('tooltip_pop');
  hideTooltip2();
  clearTimeout(tooltip_timer);
  tooltip_elem=el;
  tooltip_elem.className=tooltip_elem.getAttribute('_class_active');
  tooltip_timer=setTimeout('showTooltip2();',300);
}

function updateTooltip(e) {
  if (!e) var e=window.event;
  if (tooltip_pop!=null && tooltip_pop.style.display=='none') {
    var ns=(navigator.appName.indexOf('Netscape')!=-1);
    var x=ns ? e.pageX : e.x+(document.documentElement && document.documentElement.scrollLeft ? document.documentElement.scrollLeft : document.body.scrollLeft);
    var y=ns ? e.pageY : e.y+(document.documentElement && document.documentElement.scrollTop ? document.documentElement.scrollTop : document.body.scrollTop);
    var px=document.layers ? '' : 'px';
    tooltip_pop.style.left=x+40+px;
    tooltip_pop.style.top=y+20+px;
  }
}

function showTooltip(e) {
  if (!e) var e=window.event;
  if (this!=tooltip_elem) hideTooltip2();
  clearTimeout(tooltip_timer);
  tooltip_elem=this;
  tooltip_elem.className=tooltip_elem.getAttribute('_class_active');
  tooltip_timer=setTimeout('showTooltip2();',300);
}

function showTooltip2() {
  tooltip_pop.innerHTML='resolving ...';
  tooltip_pop.style.display='block';
  var param=tooltip_elem.getAttribute('_param');
  RSLite.call('/tooltip',param+';'+escape(tooltip_elem.innerHTML));
}

function hideTooltip(e) {
  if (!e) var e=window.event;
  if (tooltip_pop.style.display=='none') tooltip_elem.className=tooltip_elem.getAttribute('_class');
  clearTimeout(tooltip_timer);
  tooltip_timer=setTimeout('hideTooltip2();',3000);
}

function hideTooltip2() {
  if (tooltip_elem!=null) tooltip_elem.className=tooltip_elem.getAttribute('_class');
  tooltip_pop.style.display='none';
}

document.onmousemove=updateTooltip;

function ResolverCallback(str) {
  tooltip_pop.innerHTML=str;
}

function ResolverFailure() {
  tooltip_pop.innerHTML='timeout';
}

RSLite=new RSLiteObject();
RSLite.callback=ResolverCallback;
RSLite.failure=ResolverFailure;

function selectElement(element) {
  if (document.selection) {
    var range=document.body.createTextRange();
    range.moveToElementText(element);
    range.select();
  }
  else if (window.getSelection) {
    var range=document.createRange();
    range.selectNodeContents(element);
    var selection=window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
 }
}
