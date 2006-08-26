/*
 * perl antispam smtp proxy
 * (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
 * (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>
 *
 * version='1.2.0'
 * modversion=' beta 0'
 *
 */

function toggleDisp(nodeid) {
  if (nodeid.substr(0,9)=='setupItem')
    nodeid=nodeid.substr(9);
  layer=document.getElementById('treeElement'+nodeid);
  img=document.getElementById('treeIcon'+nodeid);
  if (layer.style.display=='none') {
    layer.style.display='block';
    img.src='get?file=images/minusIcon.png';
    if (document.getElementById('setupItem'+nodeid))
      document.getElementById('setupItem'+nodeid).style.display='block';
  } else {
    layer.style.display='none';
    img.src='get?file=images/plusIcon.png';
    if (document.getElementById('setupItem'+nodeid))
      document.getElementById('setupItem'+nodeid).style.display='none';
  }
}

function expand(expand, force) {
  counter=0;
  while (document.getElementById('treeElement'+counter)) {
    if (!expand) {
      //dont shrink if this element is the one passed in the URL
      arr=document.getElementById('treeElement'+counter).getElementsByTagName('a');
      txt=''; found=0;
      loc=new String(document.location);
      for(i=0; i<arr.length; i++) {
        txt=txt+arr.item(i).href;
        tmpHref=new String(arr.item(i).href);
        if (tmpHref.substr(tmpHref.indexOf('#'))==loc.substr(loc.indexOf('#'))) {
          //give this tree node the right icon
          document.getElementById('treeIcon'+counter).src='get?file=images/minusIcon.png';
          found=1;
        }
      }
      if (!found | force) {
        document.getElementById('treeIcon'+counter).src='get?file=images/plusIcon.png';
        document.getElementById('treeElement'+counter).style.display='none';
        if (document.getElementById('setupItem'+counter))
          document.getElementById('setupItem'+counter).style.display='none';
      }
    } else {
      document.getElementById('treeElement'+counter).style.display='block';
      document.getElementById('treeIcon'+counter).src='get?file=images/minusIcon.png';
      if (document.getElementById('setupItem'+counter))
        document.getElementById('setupItem'+counter).style.display='block';
    }
    counter++;
  }
}

//make the 'rel's work
function externalLinks() {
  if (!document.getElementsByTagName)
    return;
  var anchors=document.getElementsByTagName('a');
  for (var i=0; i<anchors.length; i++) {
    var anchor=anchors[i];
    if (anchor.getAttribute('href') && anchor.getAttribute('rel')=='external')
      anchor.target='_blank';
  }
}

var checkflag='false';
// chech/unchech all checkboxes
function check(field) {
  if (checkflag=='false') {
    for (var i=0; i<field.length; i++) {
      field[i].checked=true;
    }
    field.checked=true;
    checkflag='true';
  } else {
    for (var i=0; i<field.length; i++) {
      field[i].checked=false;
    }
    field.checked=false;
    checkflag='false';
  }
}

function popFileEditor(file,func) {
  var width=600;
  var height=450;
  var left=(screen.availWidth-width)/2;
  var top=(screen.availHeight-height)/2;
  window.name='main'; // for child window
  window.open(
    'edit?file='+file+'&func='+func,
    'FileEditor',
    'width='+width+',height='+height+',left='+left+',top='+top+',toolbar=no,menubar=no,location=no,personalbar=no,scrollbars=no,status=no,directories=no,resizable=no'
  );
}

function popFileViewer(collection,file,search) {
  var width=3*screen.availWidth/4;
  var height=3*screen.availHeight/4;
  var left=(screen.availWidth-width)/2;
  var top=(screen.availHeight-height)/2;
  window.name='main'; // for child window
  window.open(
    'view?collection='+collection+'&file='+file+'&search='+search,
    'FileViewer',
    'width='+width+',height='+height+',left='+left+',top='+top+',toolbar=no,menubar=no,location=no,personalbar=no,scrollbars=yes,status=no,directories=no,resizable=yes'
  );
}

window.onload=externalLinks;
