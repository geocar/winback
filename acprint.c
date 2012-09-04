#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <time.h>

#include <aclapi.h>

#ifdef WINVER
#undef WINVER
#endif
#define WINVER	0x0500
#include "sddl.h"

#include "acprint.h"
#include "local.h"

int vbprint(FILE *fp, const char *s)
{
	int state;
	if (!s) {
		fprintf(fp, "Nothing");
	} else {
		state = 0;
		while (*s) {
			if (*s < ' ' || *s == '"' || *s >= 127) {
				switch (state) {
				case 0: break;
				case 1: fputc('"', fp); /* fall through */
				case 2: fputc('&', fp);
				};
				fprintf(fp, "Chr(%d)",*s);
				state = 2;
			} else {
				switch (state) {
				case 1: break;
				case 0: /* fall through */
				case 2: fputc('"', fp);
				};
				fputc(*s, fp);
				state = 1;
			}
			s++;
		}
		if (state == 1) {
			fputc('"', fp);
		}
	}
	return 1;
}
int sidprint(FILE *fp, PSID sid)
{
	static char buf1[256];
	static char buf2[256];
	char *p1, *p2;
	DWORD buf1size, buf2size;
	SID_NAME_USE ot;
	LPTSTR s;


	if (!sid) {
		fprintf(fp, "Nothing");
		return 1;
	}

	if (!ConvertSidToStringSid(sid, &s)) return 0;

	if (strcasecmp(s, "S-1-1-0") == 0) {
		fprintf(fp, "SID_EVERYONE");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-3-1") == 0) {
		fprintf(fp, "SID_CREATOR_GROUP");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-3-0") == 0) {
		fprintf(fp, "SID_CREATOR_OWNER");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-1") == 0) {
		fprintf(fp, "SID_DIALUP");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-2") == 0) {
		fprintf(fp, "SID_NETWORK");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-3") == 0) {
		fprintf(fp, "SID_BATCH");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-4") == 0) {
		fprintf(fp, "SID_INTERACTIVE");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-6") == 0) {
		fprintf(fp, "SID_SERVICE");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-7") == 0) {
		fprintf(fp, "SID_ANONYMOUS_LOGIN");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-8") == 0) {
		fprintf(fp, "SID_PROXY");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-9") == 0) {
		fprintf(fp, "SID_ENTERPRISE_DOMAIN");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-10") == 0) {
		fprintf(fp, "SID_PRINCIPAL_SELF");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-11") == 0) {
		fprintf(fp, "SID_AUTHENTICATED_USERS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-12") == 0) {
		fprintf(fp, "SID_RESTRICTED");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-13") == 0) {
		fprintf(fp, "SID_TERMINAL_SERVER_USERS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-18") == 0) {
		fprintf(fp, "SID_LOCAL_SYSTEM");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-19") == 0) {
		fprintf(fp, "SID_LOCAL_SERVICE");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-20") == 0) {
		fprintf(fp, "SID_NETWORK_SERVICE");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-544") == 0) {
		fprintf(fp, "SID_ADMINISTRATORS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-545") == 0) {
		fprintf(fp, "SID_USERS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-546") == 0) {
		fprintf(fp, "SID_GUESTS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-547") == 0) {
		fprintf(fp, "SID_POWER_USERS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-548") == 0) {
		fprintf(fp, "SID_ACCOUNT_OPERATORS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-549") == 0) {
		fprintf(fp, "SID_SERVER_OPERATORS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-550") == 0) {
		fprintf(fp, "SID_PRINT_OPERATORS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-551") == 0) {
		fprintf(fp, "SID_BACKUP_OPERATORS");
		LocalFree(s);
		return 1;

	} else if (strcasecmp(s, "S-1-5-32-552") == 0) {
		fprintf(fp, "SID_REPLICATOR");
		LocalFree(s);
		return 1;
	}

	buf1size = sizeof(buf1);
	buf2size = sizeof(buf2);
	if (!LookupAccountSid(NULL, sid, buf1, &buf1size,
				buf2, &buf2size,&ot)) {
		win32_perror("LookupAccountSid");
		if (buf1size >= sizeof(buf1)) {
			p1 = malloc(buf1size+16);
		} else {
			p1 = buf1;
		}
		if (buf2size >= sizeof(buf2)) {
			p2 = malloc(buf2size+16);
		} else {
			p2 = buf2;
		}
		if (p1 != buf1 || p2 != buf1) {
			if (!LookupAccountSid(NULL, sid, p1, &buf1size,
						p2, &buf2size, &ot)) {
				win32_perror("LookupAccountSid (2)");
				fprintf(fp, "\"%s\"", s);
				LocalFree(s);
				return 1;
			}
		}
	} else {
		p1 = buf1; p2 = buf2;
	}

	switch (ot) {
	case SidTypeUser:
		fprintf(fp, "USR(");
		break;
	case SidTypeGroup:
	case SidTypeWellKnownGroup:
		fprintf(fp, "GRP(");
		break;
	case SidTypeDomain:
		fprintf(fp, "HOST(");
		break;
	default:
		/* ugh */
		fprintf(fp, "\"%s\"", s);
		LocalFree(s);
		return 1;
	};
	vbprint(fp, p2);
	fprintf(fp, ", ");
	vbprint(fp, p1);
	fprintf(fp, ")");
	if (p1 != buf1) free(p1);
	if (p2 != buf2) free(p2);
	LocalFree(s);
	return 1;
}
int aclprint(FILE *fp, const char *base, PACL acl)
{
	const char *z;
	char ztmp[32];
	DWORD y, n, rc;
	PEXPLICIT_ACCESS pal;
	ULONG pal_len;

	rc = GetExplicitEntriesFromAcl(acl, &pal_len, &pal);
	if (rc != ERROR_SUCCESS) {
		win32_perror("GetExplicitEntriesFromAcl");
		return 0;
	}

	fprintf(fp, "Redim %s(%u)\r\n", base, (unsigned)(pal_len+1));
	for (n = 0; n < pal_len; n++) {
		switch (pal[n].grfAccessMode) {
		case SET_ACCESS:
		case GRANT_ACCESS: z = "GRANT_ACCESS"; break;

		case REVOKE_ACCESS:
		case DENY_ACCESS: z = "DENY_ACCESS"; break;

		case SET_AUDIT_SUCCESS:
		case SET_AUDIT_FAILURE:
			continue;
		default:
			sprintf(ztmp, "&H%x", pal[n].grfAccessMode);
			z = ztmp;
			break;
		};

		fprintf(fp, "%s(%u) = ACE(%s, ", base, (unsigned int)(1+n), z);

		switch (pal[n].grfAccessPermissions) {
		default:
			fprintf(fp, "&H%x", (unsigned int)pal[n].grfAccessPermissions);
			break;
		};
		fprintf(fp, ", ");
		z = "";
		y = pal[n].grfInheritance;
		if (y & CONTAINER_INHERIT_ACE) {
			fprintf(fp, "%sCONTAINER_INHERIT_ACE", z);
			y &= ~CONTAINER_INHERIT_ACE;
			z = " + ";
		}
		if (y & INHERIT_ONLY_ACE) {
			fprintf(fp, "%sINHERIT_ONLY_ACE", z);
			y &= ~INHERIT_ONLY_ACE;
			z = " + ";
		}
		if (y & NO_PROPAGATE_INHERIT_ACE) {
			fprintf(fp, "%sNO_PROPAGATE_INHERIT_ACE", z);
			y &= ~NO_PROPAGATE_INHERIT_ACE;
			z = " + ";
		}
		if (y & OBJECT_INHERIT_ACE) {
			fprintf(fp, "%sOBJECT_INHERIT_ACE", z);
			y &= ~OBJECT_INHERIT_ACE;
			z = " + ";
		}
		if ((y & SUB_CONTAINERS_AND_OBJECTS_INHERIT) == SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
			fprintf(fp, "%sSUB_CONTAINERS_AND_OBJECTS_INHERIT", z);
			y &= ~SUB_CONTAINERS_AND_OBJECTS_INHERIT;
			z = " + ";
		}
		if (y & SUB_OBJECTS_ONLY_INHERIT) {
			fprintf(fp, "%sSUB_CONTAINERS_ONLY_INHERIT", z);
			y &= ~SUB_CONTAINERS_ONLY_INHERIT;
			z = " + ";
		}
		if (y & SUB_OBJECTS_ONLY_INHERIT) {
			fprintf(fp, "%sSUB_OBJECTS_ONLY_INHERIT", z);
			y &= ~SUB_CONTAINERS_ONLY_INHERIT;
			z = " + ";
		}
		if (y != 0) {
			fprintf(fp, "%s&H%x", z, (unsigned int)y);
		} else if (!*z) {
			fprintf(fp, "0");
		}
		fprintf(fp, ", ");
		switch (pal[n].Trustee.TrusteeForm) {
		case TRUSTEE_IS_SID:
			sidprint(fp, (PSID)pal[n].Trustee.ptstrName);
			break;

		case TRUSTEE_IS_NAME:
			vbprint(fp, pal[n].Trustee.ptstrName);
			break;
		default:
			fprintf(fp, "UNKNOWN_TRUSTEE");
			break;
		};

		fprintf(fp, ")\r\n");
	}
	return 1;
}

void acprint_const(FILE *fp)
{
	char ct[25];
	time_t now;

	time(&now);
	strcpy(ct, ctime(&now));
	ct[24] = '\0';

	fprintf(fp, "' This file was created by winback.exe on %s\r\n", ct);

	fprintf(fp, "Option Explicit\r\n\r\n"
		"Dim Filename, Owner, Group\r\n"
		"Redim SACL(0), DACL(0)\r\n\r\n");
	fprintf(fp, "Dim wsh, objLocator, objService, getenv\r\n"
		"Set wsh = CreateObject(\"WScript.Shell\")\r\n"
		"Set getenv = wsh.Environment(\"Process\")\r\n"
		"Set objLocator = CreateObject(\"WbemScripting.SWbemLocator\")\r\n"
		"Set objService = objLocator.ConnectServer(getenv(\"COMPUTERNAME\"), \"root\\cimv2\")\r\n"
		"objService.Security_.impersonationlevel = 3\r\n"
		"objService.Security_.Privileges.AddAsString \"SeSecurityPrivilege\", TRUE\r\n"
		"objService.Security_.Privileges.AddAsString \"SeRestorePrivilege\", TRUE\r\n"
		"\r\n");

	fprintf(fp, "Const CONTAINER_INHERIT_ACE              = &H%x\r\n", CONTAINER_INHERIT_ACE);
	fprintf(fp, "Const INHERIT_ONLY_ACE                   = &H%x\r\n", INHERIT_ONLY_ACE);
	fprintf(fp, "Const NO_PROPAGATE_INHERIT_ACE           = &H%x\r\n", NO_PROPAGATE_INHERIT_ACE);
	fprintf(fp, "Const OBJECT_INHERIT_ACE                 = &H%x\r\n", OBJECT_INHERIT_ACE);
	fprintf(fp, "Const SUB_CONTAINERS_AND_OBJECTS_INHERIT = &H%x\r\n", 
			SUB_CONTAINERS_AND_OBJECTS_INHERIT);
	fprintf(fp, "Const SUB_OBJECTS_ONLY_INHERIT           = &H%x\r\n", 
			SUB_OBJECTS_ONLY_INHERIT);
	fprintf(fp, "Const SUB_CONTAINERS_ONLY_INHERIT        = &H%x\r\n", 
			SUB_CONTAINERS_ONLY_INHERIT);

	fprintf(fp, "\r\n");
	fprintf(fp, "Const NOT_USED_ACCESS   = 0\r\n");
	fprintf(fp, "Const GRANT_ACCESS      = 1\r\n");
	fprintf(fp, "Const SET_ACCESS        = 2\r\n");
	fprintf(fp, "Const DENY_ACCESS       = 3\r\n");
	fprintf(fp, "Const REVOKE_ACCESS     = 4\r\n");
	fprintf(fp, "Const SET_AUDIT_SUCCESS = 5\r\n");
	fprintf(fp, "Const SET_AUDIT_FAILURE = 6\r\n");
	fprintf(fp, "\r\n");

	fprintf(fp, 
			"Const SID_EVERYONE = \"S-1-1-0\"\r\n"
			"Const SID_CREATOR_GROUP = \"S-1-3-1\"\r\n"
			"Const SID_CREATOR_OWNER = \"S-1-3-0\"\r\n"
			"Const SID_DIALUP = \"S-1-5-1\"\r\n"
			"Const SID_NETWORK = \"S-1-5-2\"\r\n"
			"Const SID_BATCH = \"S-1-5-3\"\r\n"
			"Const SID_INTERACTIVE = \"S-1-5-4\"\r\n"
			"Const SID_SERVICE = \"S-1-5-6\"\r\n"
			"Const SID_ANONYMOUS_LOGIN = \"S-1-5-7\"\r\n"
			"Const SID_PROXY = \"S-1-5-8\"\r\n"
			"Const SID_ENTERPRISE_DOMAIN = \"S-1-5-9\"\r\n"
			"Const SID_PRINCIPAL_SELF = \"S-1-5-10\"\r\n"
			"Const SID_AUTHENTICATED_USERS = \"S-1-5-11\"\r\n"
			"Const SID_RESTRICTED = \"S-1-5-12\"\r\n"
			"Const SID_TERMINAL_SERVER_USERS = \"S-1-5-13\"\r\n"
			"Const SID_LOCAL_SYSTEM = \"S-1-5-18\"\r\n"
			"Const SID_LOCAL_SERVICE = \"S-1-5-19\"\r\n"
			"Const SID_NETWORK_SERVICE = \"S-1-5-20\"\r\n"
			"Const SID_ADMINISTRATORS = \"S-1-5-32-544\"\r\n"
			"Const SID_USERS = \"S-1-5-32-545\"\r\n"
			"Const SID_GUESTS = \"S-1-5-32-546\"\r\n"
			"Const SID_POWER_USERS = \"S-1-5-32-547\"\r\n"
			"Const SID_ACCOUNT_OPERATORS = \"S-1-5-32-548\"\r\n"
			"Const SID_SERVER_OPERATORS = \"S-1-5-32-549\"\r\n"
			"Const SID_PRINT_OPERATORS = \"S-1-5-32-550\"\r\n"
			"Const SID_BACKUP_OPERATORS = \"S-1-5-32-551\"\r\n"
			"Const SID_REPLICATOR = \"S-1-5-32-552\"\r\n"
		"\r\n");

	fprintf(fp,
		"Function ACE(a,b,c,d)\r\n"
		"    Dim e\r\n"
		"    Set e = objService.Get(\"Win32_Ace\").Spawninstance_\r\n"
		"    e.Properties_.item(\"AceType\") = a\r\n"
		"    e.Properties_.item(\"AccessMask\") = b\r\n"
		"    e.Properties_.item(\"AceFlags\") = c\r\n"
		"    e.Properties_.item(\"Trustee\") = d\r\n"
		"    ACE = e\r\n"
		"End Function\r\n\r\n"

		"Function Quote(s)\r\n"
		"    Dim i, c, r\r\n"
		"    r = \"\"\r\n"
		"    For i = 1 To Len(s)\r\n"
		"        c = Mid(s, i, 1)\r\n"
		"        If c <> Chr(34) And c <> 92 Then\r\n"
		"            r = r & c\r\n"
		"        Else\r\n"
		"            r = r & c & c\r\n"
		"        End If\r\n"
		"    Next\r\n"
		"    Quote = r\r\n"
		"End Function\r\n\r\n"

		"Function USR(d,n)\r\n"
		"    Dim nq, q, r, x\r\n"
		"    q = \"\"\r\n"
		"    If d <> \"\" Then q = \"Domain = \"\"\" & Quote(d) & \"\"\" AND \"\r\n"
		"    q = q & \"Name = \"\"\" & Quote(n) & \"\"\"\"\r\n"
		"    nq = \"SELECT Sid, Domain, Name FROM Win32_UserAccount WHERE SIDType=1 AND \" & q\r\n"
		"    Set r = objService.ExecQuery(q,,0)\r\n"
		"    If r.Count <> 0 Then\r\n"
		"        For Each x In r\r\n"
		"            Set USR = x.Sid\r\n"
		"        Next\r\n"
		"    Else\r\n"
		"        WScript.Echo \"Cannot locate USR \" & q\r\n"
		"        Set USR = Nothing\r\n"
		"    End If\r\n"
		"End Function\r\n\r\n"

		"Function GRP(d,n)\r\n"
		"    Dim nq, q, r, x\r\n"
		"    q = \"\"\r\n"
		"    If d <> \"\" Then q = \"Domain = \"\"\" & Quote(d) & \"\"\" AND \"\r\n"
		"    q = q & \"Name = \"\"\" & Quote(n) & \"\"\"\"\r\n"
		"    Set r = objService.Get(\"Win32_Group.\" & q)\r\n"
		"    If Not r Is Nothing Then\r\n"
		"        Set GRP = r.Sid\r\n"
		"    Else\r\n"
		"        WScript.Echo \"Cannot locate GRP \" & q\r\n"
		"        Set GRP = Nothing\r\n"
		"    End If\r\n"
		"End Function\r\n\r\n"

		"Function HOST(d,n)\r\n"
		"    Dim nq, q, r, x\r\n"
		"    q = \"\"\r\n"
		"    If d <> \"\" Then q = \"Domain = \"\"\" & Quote(d) & \"\"\" AND \"\r\n"
		"    q = q & \"Name = \"\"\" & Quote(n) & \"\"\"\"\r\n"
		"    Set r = objService.Get(\"Win32_ComputerSystem.\" & q)\r\n"
		"    If Not r Is Nothing Then\r\n"
		"        Set HOST = r.Sid\r\n"
		"    Else\r\n"
		"        WScript.Echo \"Cannot locate HOST\" & q\r\n"
		"        Set HOST = Nothing\r\n"
		"    End If\r\n"
		"End Function\r\n\r\n"

		"Function Trustee(s)\r\n"
		"    Dim x, y\r\n"
		"    Set x = objService.Get(\"Win32_Trustee\").Spawninstance_\r\n"
		"    Set y = objService.Get(\"Win32_SID.SID=\"\"\" & s & \"\"\"\")\r\n"
		"    x.Domain = y.ReferencedDomainName\r\n"
		"    x.Name = y.AccountName\r\n"
		"    x.Properties_.item(\"SID\") = y.BinaryRepresentation\r\n"
		"    x.Properties_.item(\"SidLength\") = y.SidLength\r\n"
		"    x.Properties_.item(\"SIDString\") = y.Sid\r\n"
		"    Set Trustee = x\r\n"
		"End Function\r\n\r\n"

		"Sub Process()\r\n"
		"    Dim d, f, m, p, r\r\n"
		"    Set f = objService.Get(\"Win32_LogicalFileSecuritySetting.Path=\"\"\" & Quote(Filename) & \"\"\"\")\r\n"
		"    Set d = objService.Get(\"Win32_SecurityDescriptor\").Spawninstance_\r\n"
		"    Set m = f.Methods_(\"SetSecurityDescriptor\")\r\n"
		"    Set p = m.inParameters.SpawnInstance_()\r\n"
		"    d.Properties_.item(\"Owner\") = Owner\r\n"
		"    d.Properties_.item(\"Group\") = Group\r\n"
		"    d.Properties_.item(\"DACL\") = DACL\r\n"
		"    d.Properties_.item(\"SACL\") = SACL\r\n"
		"    p.Properties_.item(\"Descriptor\") = d\r\n"
		"    Set r = f.ExecMethod_(\"SetSecurityDescriptor\", p)\r\n"
		"    If r.ReturnValue <> 0 Then\r\n"
		"        WScript.Echo \"Error processing \" & Filename & \", error=\" & r.ReturnValue\r\n"
		"    End If\r\n"
		"End Sub\r\n\r\n\r\n"
		);
}


int acprint(FILE *fp, PSECURITY_DESCRIPTOR sec, const char *filename)
{
	PSID sid;
	PACL acl;
	BOOL ignored, valid;


	fprintf(fp, "Filename=");
	vbprint(fp, filename);
	fprintf(fp, "\r\n");

	sid = NULL;
	if (!GetSecurityDescriptorOwner(sec, &sid, &ignored)) {
		win32_perror("GetSecurityDescriptorOwner");
		fprintf(fp, "Owner=Nothing\r\n");
	} else {
		fprintf(fp,"Owner=");
		sidprint(fp, sid);
		fputc('\r', fp);
		fputc('\n', fp);
	}

	sid = NULL;
	if (!GetSecurityDescriptorGroup(sec, &sid, &ignored)) {
		win32_perror("GetSecurityDescriptorGroup");
		fprintf(fp, "Group=Nothing\r\n");
	} else {
		fprintf(fp,"Group=");
		sidprint(fp, sid);
		fputc('\r', fp);
		fputc('\n', fp);
	}

	acl = NULL;
	if (!GetSecurityDescriptorSacl(sec, &valid, &acl, &ignored)) {
		win32_perror("GetSecurityDescriptorSacl");
	} else {
		aclprint(fp, "SACL", acl);
	}

	acl = NULL;
	if (!GetSecurityDescriptorDacl(sec, &valid, &acl, &ignored)) {
		win32_perror("GetSecurityDescriptorDacl");
	} else {
		aclprint(fp, "DACL", acl);
	}

	fprintf(fp, "Process()\r\n\r\n");

	return 1;
}
