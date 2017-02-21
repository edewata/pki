<!-- --- BEGIN COPYRIGHT BLOCK ---
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation; version 2 of the License.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

     Copyright (C) 2007 Red Hat, Inc.
     All rights reserved.
     --- END COPYRIGHT BLOCK --- -->
<html>
<head>
<title>CA End-Entity</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<link rel="shortcut icon" href="/pki/images/favicon.ico" />
<script src="/pki/js/jquery.js"></script>
<script src="/pki/js/jquery.i18n.properties.js"></script>
<script src="/pki/js/underscore.js"></script>
<script src="/pki/js/backbone.js"></script>
<script src="/pki/js/pki.js"></script>
<script src="/pki/js/pki-warning.js"></script>
<SCRIPT LANGUAGE="JavaScript"></SCRIPT>
<script lang="javascript" src="/dynamicVars.js"></script>
<script lang="javascript" src="../cms-funcs.js"></script>
<script lang="javascript">
<!--//
function doResize() {
    // used by tabs.html
    // don't call resize for IE - it sometimes crashes
    if (navigator.appName == 'Netscape' &&
        ((navMajorVersion() < 4) ||
         (typeof(crypto.version) == "undefined"))) {
        top.reloadTabs(-1);
    }
}

function tabItem(name, link, menu, defaultIndex)
{
	this.name = name;
	this.blackname = name.fontcolor('black');
	this.whitename = name.fontcolor('white');
	this.link = link;
	this.menu = menu;
	this.defaultIndex = defaultIndex;
	this.currentIndex = defaultIndex;
}

function initTabs()
{

	top.tabs = new Array();

	var name;
    top.tabsCount=0;

	name = 'Enrollment';
	top.tabs[top.tabsCount++] = new tabItem(name, 'enrollMenu.html', 
								 top.EnrollMenu, 1);
	if (http != 'true') {
	  name = 'Renewal';
	  top.tabs[top.tabsCount++] = new tabItem(name, 'renewalMenu.html',
	  							 top.RenewalMenu, 0);
	  name = 'Revocation';
	  top.tabs[top.tabsCount++] = new tabItem(name, 'revocationMenu.html',
								 top.RevocationMenu, 0);
	}

	name = 'Retrieval';
	top.tabs[top.tabsCount++] = new tabItem(name, 'retrievalMenu.html',
								 top.RetrievalMenu, 0);

    top.tabsSelectedIndex = 0;

}


function menuItem(name, link, desc)
{
	this.name = name;
	this.link = link;
	this.seldesc   = desc.fontcolor('blue');  // text when selected
	this.unseldesc = desc.fontcolor('black');   // text when unselected
	this.desc = desc;
}

function initMenus()
{
	initEnrollMenu();
	if (http != 'true') {
	  initRenewalMenu();
	  initRevocationMenu();
	}
	initRecoveryMenu();
	initRetrievalMenu();
}

function initRenewalMenu()
{
	top.RenewalMenu = new Array();

	var name = 'usercert';
	top.RenewalMenu[0] = new menuItem(name, 'UserRenewal.html',
						   'User Certificate');
	//name = 'servercert';
	//top.RenewalMenu[name] = new menuItem(name, 'ServerRenewal.html',
	//					   'Server Certificate');
}

function tableItem(name, items)
{
	this.name = name; 
	this.menuItems = items;
}


// Check if a particular authmanager is enabled.
// The 'authamanager' array is set in 
// dynamic javascript in the URL /dynamicVars.js

function isAuthMgrEnabled(name)
{
	// handle the case when no auth manager is configured
        if (typeof(authmanager) == 'undefined') {
               return false;
        }
	for (var k=0; k<authmanager.length; k++) {
		if (authmanager[k] == name) {
			return true;
		}
	}
	return false;
}

function initEnrollMenu()
{
	top.EnrollMenu = new Array();

	var item;
    var count=0;
    menuItems = new Array();
   // User enrollment stuff here

    item = 'userenrolltitle';
    menuItems[count] = top.EnrollMenu[count] = 
	    new menuItem(item, '', 'Browser');
    count++;

	// 'Manual' enrollment - does not pass through any
	// authentication plugin, so requests must be approved
	// manually by the agent

	item = 'manuser';
	menuItems[count] = top.EnrollMenu[count] = 
	    new menuItem(item, 'ManUserEnroll.html', 'Manual');
    count++;


	// UidPwdDirAuth - authenticates against an LDAP directory
	//    with uid + pwd

	if ( isAuthMgrEnabled("UidPwdDirAuth") ) {
		item = 'diruser';
		menuItems[count] = top.EnrollMenu[count] = 
    		new menuItem(item, 'DirUserEnroll.html', 
					 	'Directory');
    	count++;
	}

	// UidPwdPinDirAuth - authenticates against an LDAP directory
	//    with uid + pwd + one-time pin
	if ( isAuthMgrEnabled("UidPwdPinDirAuth") ) {
		item = 'pinuser';
		menuItems[count] = top.EnrollMenu[count] = 
    		new menuItem(item, 'DirPinUserEnroll.html', 
					 	 	'Directory and Pin');
    	count++;
	}

	// Kerberos - authenticates against a Kerberos server
	if ( isAuthMgrEnabled("KerberosAuth") ) {
		item = 'kerberos';
		menuItems[count] = top.EnrollMenu[count] = 
			new menuItem(item, 'KerberosBasedAuthentication.html', 'Kerberos');
    	count++;
	}

	// PortalEnroll - allows a user to enroll if their uid
	// does NOT already exist in the directory. I.e. they can
	// create an account
	if ( isAuthMgrEnabled("PortalEnroll") ) {
		item = 'portaluser';
		menuItems[count] = top.EnrollMenu[count] = 
			new menuItem(item, 'PortalEnrollment.html', 'Portal');
    	count++;
	}

  if (subsystemname != 'ra') {
      if (http != 'true') {
        // this one is directory based cert-based
	if ( isAuthMgrEnabled("UidPwdDirAuth") ) {
	  item = 'certBasedDualEnroll';
	  menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, 'CertBasedDualEnroll.html', 'Certificate');
          count++;
        }
      }
 }
 else {
     if (http != 'true') {
        // this one is directory based cert-based
	if ( isAuthMgrEnabled("UidPwdDirAuth") ) {
	  item = 'certBasedSingleEnroll';
	  menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, 'CertBasedSingleEnroll.html', 'Certificate');
          count++;
        }
     }
 
//	item = 'certBasedEncEnroll';
//	menuItems[count] = top.EnrollMenu[count] = 
//		new menuItem(item, 'CertBasedEncryptionEnroll.html', 'Certificate');
//   count++;
//	item = 'certBasedSingleEnroll';
//	menuItems[count] = top.EnrollMenu[count] = 
//		new menuItem(item, 'CertBasedSingleEnroll.html', 'Certificate');
//   count++;

      }
// Server Enrollment
	item = 'serverenrolltitle';
	menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, '', 'Server');
    count++;

	item = 'manserver';
	menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, 'ManServerEnroll.html', 'SSL Server');
    count++;

	// if we're talking to a Registration Manager, don't allow the user to enroll
	// for a RM or CM certificate.
	item = 'manra';
		menuItems[count] = top.EnrollMenu[count] = 
			new menuItem(item, 'ManRAEnroll.html', 'Registration Manager');
    count++;

  if (subsystemname != 'ra') {
	item = 'manca';
	menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, 'ManCAEnroll.html', 'Certificate Manager');
    count++;
  }

    item = 'manocsp';
    menuItems[count] = top.EnrollMenu[count] =
        new menuItem(item, 'OCSPResponder.html', 'OCSP Responder');
    count++;

	item = 'othertitle';
	menuItems[count] = top.EnrollMenu[count] = 
		new menuItem(item, '', 'Other');
    count++;

    item = 'manos';
    menuItems[count] = top.EnrollMenu[count] =
        new menuItem(item, 'ManObjSignEnroll.html', 'Object Signing (Browser)');
    count++;

    item = 'manospkcs';
    menuItems[count] = top.EnrollMenu[count] =
        new menuItem(item, 'ObjSignPKCS10Enroll.html', 'Object Signing (PKCS10)');
    count++;
    
    item = 'mancmc';
    menuItems[count] = top.EnrollMenu[count] =
        new menuItem(item, 'CMCEnrollment.html', 'CMC Enrollment');
    count++;

}

function initRevocationMenu()
{
	top.RevocationMenu = new Array();

	var name='usercert';
	top.RevocationMenu[0] = new menuItem(name, 'UserRevocation.html',
							  'User Certificate');
	//name='servercert';
	//top.RevocationMenu[1] = new menuItem(name, 'ServerRevocation.html',
	//					      'Server Certificate');

    name='othercert';
    top.RevocationMenu[1] = new menuItem(name, 'ChallengeRevoke1.html',
                              'Certificate (challenge phrase-based)');
    name='othercert';	
    top.RevocationMenu[2] = new menuItem(name, 'CMCRevReq.html',
                              'CMC Revoke');
}

function initRecoveryMenu()
{
	top.RecoveryMenu = new Array();
	var name;

	name = 'keyRecovery';
	top.RecoveryMenu[0] = new menuItem(name, 'KeyRecovery.html',
							'Key Recovery');
}

function initRetrievalMenu()
{
	top.RetrievalMenu = new Array();
	var name;
	var count=0;

	name = 'checkrequest';
	top.RetrievalMenu[count++] = new menuItem(name, 'checkRequest.html',
							 'Check Request Status');

  if (subsystemname != 'ra') {
	name = 'listcerts';
	top.RetrievalMenu[count++] = new menuItem(name, 'queryBySerial.html',
							 'List Certificates');
	name = 'searchcerts';
	top.RetrievalMenu[count++] = new menuItem(name, 'srchCert.html',
							 'Search Certificates');
  }
	name = 'getcachain';
	top.RetrievalMenu[count++] = new menuItem(name, 'GetCAChain.html',
							 'Import CA Certificate Chain');

  if (subsystemname != 'ra') {
	name = 'reviewcrl';
	if (clacrlurl != '') {
		top.RetrievalMenu[count++] = new menuItem(name, clacrlurl,
					 'Import Certificate Revocation List');
	} else {
		top.RetrievalMenu[count++] = new menuItem(name, '/getInfo?template=toDisplayCRL',
					 'Import Certificate Revocation List');
	}
  }
}

// This method draws the left panel

function loadMenu(menu)
{

	with (top.left.document) {
        writeln('<body bgcolor="#cccccc" vlink="#444444" link="#444444" alink="#333399">');
		writeln('<table border=0 width=130 cellspacing=4 cellpadding=4>');
		writeln('<tr>');
		writeln('<td>');

		var selbgcol   = '#cccccc';  // cell's background col when selected
		var unselbgcol = '#cccccc';  //   ""          ""           unselected

		for (var k=0; k<menu.length; k++) {
			writeln('<tr>');

			// We check if the link is empty. If it is, this means the
			// menu item should be rendered as a 'title'. See the
			// 'Browser' heading in initEnrollMenu as an example

            if (menu[k].link != '') {

    			if (k == top.tabs[top.tabsSelectedIndex].currentIndex) {

					// Draw the current element in 'selected' state

	    			writeln('<td bgcolor="'+selbgcol+'">');
		    		writeln('<font size="-1" face="PrimaSans BT, Verdana, sans-serif">'+
							'<b>'+
							'<a onclick=javascript:top.reloadMenu("'+k+'"); href='+
								menu[k].link+
							' target="cms_content" >'+
							menu[k].seldesc+'</b></a></font>'
							);
			    }
    			else {
					// Draw the current element in 'unselected' state

	    			writeln('<td bgcolor="'+unselbgcol+'">');
		    		writeln('<font size="-1" face="PrimaSans BT, Verdana, sans-serif">'+
							'<b>'+
							'<a onclick=javascript:top.reloadMenu("'+k+'"); href='+
								menu[k].link+
							' target="cms_content" >'+
							menu[k].unseldesc+'</b></a></font>'
							);

        		}

          }
          else {   // nice headers go here (enrollment menu)
          		writeln('<td bgcolor=white>'+
						'<font face="PrimaSans BT, Verdana, sans-serif"'+
						'color=black>'+
						'<b>'+
                	menu[k].desc+'</b></font>');
               }


			writeln('</td>');
			writeln('</tr>');
		}

		writeln('</table>');
		writeln('</td>');
		writeln('</tr>');
		writeln('</table>');
		close();
	}

}

function reloadMenu(item)
{
	var curMenu = top.tabs[top.tabsSelectedIndex];
	curMenu.currentIndex = item;
	top.cms_content.location = curMenu.menu[item].link;
	loadMenu(curMenu.menu);


}


function reloadMenuAndContent()
{
	var tab = top.tabs[top.tabsSelectedIndex];
	tab.currentIndex = tab.defaultIndex;
	top.cms_content.location = tab.menu[tab.currentIndex].link;
	reloadMenu(tab.currentIndex);
}

function reloadTabs(tabnum)
{
    if (tabnum != -1) {
        top.tabsSelectedIndex = tabnum;
    }
    top.reloadMenuAndContent();

    if (navigator.appName != "Netscape") {
        top.reloadMenu(top.tabs[tabnum].defaultIndex);
    }

    if ( navigator.appName == 'Netscape') {
        top.tabsf.location.reload(false);
    } else {
       loadTabs();
    }
    if ( navigator.appName != 'Netscape') {
       loadTabs();
    }
}



function loadTabs()
{
	with (top.tabsf.document) {
        writeln('<body onresize="top.doResize();" bgcolor="#9999cc" link="#FFFFFF" vlink="#FFFFFF" alink="#CCCCFF">');

		writeln('<table border=0 width="100%" cellspacing="0" cellpadding="0" bgcolor="#9999CC">');
		writeln('<tr><td>');
		writeln('<table border=0 cellspacing=0 cellpadding=0 width="100%" >');
		writeln('<tr><td>');
		writeln('<table border=0 cellspacing=12 cellpadding=0 width="100%">');
		writeln('<tr>');
		writeln('<td><font size="-1" face="PrimaSans BT, Verdana, sans-serif" color="white">Netscape<font color="#cccccc" size="-2">&reg;</font>'+
            '<b><br>Certificate Management<br> System</b></font><font size="+1" face="PrimaSans BT, Verdana, sans-serif" color="white"><b></b></font></td>');
		writeln('<td></td>');
	if (subsystemname == 'ca') {
		writeln('<td width=350 align=right><font size="+1" face="PrimaSans BT, Verdana, sans-serif" color="white"><b>Certificate Manager</b></font></td>');
	}
	else {
		writeln('<td width=350><font size="+1" face="PrimaSans BT, Verdana, sans-serif" color="white"><b>Registration Manager</b></font></td>');
	}
		writeln('</tr>');
		writeln('</table>');
		writeln('</td></tr>');
		writeln('</table>');

		writeln('<table border=0 cellspacing="0" cellpadding="0">');
		writeln('<tr>');
		writeln('<td><img src="/pki/images/spacer.gif" width="12" height="12"></td>');

		var index = top.tabsSelectedIndex;
		for (var j=0; j < top.tabsCount; j++) {
			if (j == index) {
				writeln('<td><img src="/pki/images/lgLeftTab.gif" width="13" height="21"></td>');
				writeln('<td bgcolor="#cccccc" nowrap>'); 
				writeln('<font size="-1" face="PrimaSans BT, Verdana, sans-serif"><b>'+
                    top.tabs[j].blackname+
                    '</b></font></td>');
				writeln('<td><img src="/pki/images/lgRightTab2.gif" width="16" height="21">'+
                '</td>');
			}
			else {
				writeln('<td><img src="/pki/images/dgLeftTab.gif" width="13" height="21"></td>');
				writeln('<td bgcolor="#999999" nowrap>'+
                    '<font size="-1" face="PrimaSans BT, Verdana, sans-serif">'+
				    '<a onclick=javascript:top.reloadTabs("'+
                    j+'"); href='+
                    top.tabs[j].link+' target="left"><b>'+
                    top.tabs[j].whitename+'</b></a></font></td>');
				writeln('<td><img src="/pki/images/dgRightTab2.gif" width="16" height="21"></td>');
			}
		}

		writeln('</tr>');
		writeln('</table></td></tr>');
        writeln('<tr bgcolor=#CCCCCC><td>&nbsp;<br>&nbsp;</td></tr>');
		writeln('</tr>');
		writeln('</table>');
		close();

	}
}



//-->
</script>
</head>

<script lang="javascript">
<!--//
initMenus();
initTabs();
//-->
</script>


<frameset rows="105,1*" frameborder="NO" border="0" cols="*"> 
  <frame src="tabs.html" name="tabsf" frameborder="NO" NORESIZE scrolling="NO" marginwidth="0" marginheight="0">
  <frameset cols="140,1*" border="0" frameborder="NO"> 
    <frame src="enrollMenu.html" NORESIZE frameborder="NO" marginwidth="0" marginheight="0" name="left">
    <frame src="ManUserEnroll.html" marginwidth="16" marginheight="16" frameborder="NO" NORESIZE name="cms_content">
  </frameset>
  <frame src="blank.html" name="foot" NORESIZE scrolling="NO" frameborder="NO">
</frameset>
<noframes><body bgcolor="#FFFFFF">

</body></noframes>
</html>
