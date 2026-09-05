#include <json-c/json.h>
#include <stdio.h>
#include "mudparser.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mudfile.json>\n", argv[0]);
        return 2;
    }
    MudFileInfo *mfi = parseMudFile(argv[1]);
    if (!mfi) {
        fprintf(stderr, "parseMudFile returned NULL\n");
        return 1;
    }

    printf("mud-version=%s\n", mfi->mudVersion ? mfi->mudVersion : "(null)");
    printf("mud-url=%s\n", mfi->mudUrl ? mfi->mudUrl : "(null)");
    printf("systeminfo=%s\n", mfi->systeminfo ? mfi->systeminfo : "(null)");
    printf("from-device-policy access-list count=%d\n", mfi->fromAccessListCount);
    for (int i = 0; i < mfi->fromAccessListCount; i++) {
        printf("  from-access-list[%d].name=%s\n", i, mfi->fromAccessList[i].aclName);
    }
    printf("to-device-policy access-list count=%d\n", mfi->toAccessListCount);
    for (int i = 0; i < mfi->toAccessListCount; i++) {
        printf("  to-access-list[%d].name=%s\n", i, mfi->toAccessList[i].aclName);
    }
    printf("acl count=%d\n", mfi->aclListCount);
    for (int i = 0; i < mfi->aclListCount; i++) {
        AclEntry *acl = &mfi->acls[i];
        printf("  acl[%d] name=%s type=%s ace_count=%d\n", i, acl->aclName, acl->aclType, acl->aceCount);
        for (int j = 0; j < acl->aceCount; j++) {
            AceEntry *ace = &acl->aceList[j];
            printf(
                "    ace[%d] rule-name=%s protocol=%s dnsname=%s lowerPort=%s upperPort=%s forwarding=%s direction=%s\n",
                j,
                ace->ruleName ? ace->ruleName : "(null)",
                ace->protocol ? ace->protocol : "(null)",
                ace->dnsName ? ace->dnsName : "(null)",
                ace->lowerPort ? ace->lowerPort : "(null)",
                ace->upperPort ? ace->upperPort : "(null)",
                ace->actionsForwarding ? ace->actionsForwarding : "(null)",
                ace->directionInitiated ? ace->directionInitiated : "(null)"
            );
        }
    }

    freeMudFileInfo(mfi);
    return 0;
}
