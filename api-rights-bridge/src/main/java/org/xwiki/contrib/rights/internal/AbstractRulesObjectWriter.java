/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.rights.internal;

import javax.inject.Inject;
import javax.inject.Named;

import org.xwiki.contrib.rights.RulesObjectWriter;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.objects.classes.PropertyClass;

/**
 * @version $Id$
 */
public abstract class AbstractRulesObjectWriter implements RulesObjectWriter
{

    static final String USERS_FIELD_RIGHTS_OBJECT = "users";

    static final String GROUPS_FIELD_RIGHTS_OBJECT = "groups";

    static final String LEVELS_FIELD_RIGHTS_OBJECT = "levels";

    @Inject
    @Named("compactwiki")
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    /**
     * Translates a {@link ReadableSecurityRule} into a {@link BaseObject}.
     * <p>
     * It's the caller responsibility to call this on a valid right object (depending on what's the desired behavior,
     * the <code>right</code>'s XClass should be, but not limited to {@link #XWIKI_RIGHTS_CLASS} or
     * {@link #XWIKI_GLOBAL_RIGHTS_CLASS}.
     *
     * @param right the BaseObject to which the properties of the <code>rule</code> will be copied to
     * @param rule
     */
    void copyRuleIntoBaseObject(BaseObject right, ReadableSecurityRule rule, XWikiContext context)
    {
        if (null != right) {
            if (null != rule.getState()) {
                right.setIntValue(XWikiConstants.ALLOW_FIELD_NAME,
                    rule.getState().getValue() == RuleState.DENY.getValue() ? 0 : 1);
            }
            PropertyClass groups = (PropertyClass) right.getXClass(context).get(GROUPS_FIELD_RIGHTS_OBJECT);
            PropertyClass users = (PropertyClass) right.getXClass(context).get(USERS_FIELD_RIGHTS_OBJECT);
            PropertyClass levels = (PropertyClass) right.getXClass(context).get(LEVELS_FIELD_RIGHTS_OBJECT);
            if (null != groups) {
                BaseProperty<?> groupsProperty = groups.fromValue("");
                if (null != rule.getGroups()) {
                    groupsProperty = groups.fromStringArray(rule.getGroups().stream()
                        .map(k -> entityReferenceSerializer.serialize(k, right.getDocumentReference()))
                        .toArray(String[]::new));
                }
                right.set(GROUPS_FIELD_RIGHTS_OBJECT, groupsProperty.getValue(), context);
            }

            if (null != users) {
                BaseProperty<?> usersProperty = users.fromString("");
                if (null != rule.getUsers()) {
                    usersProperty = users.fromStringArray(rule.getUsers().stream()
                        .map(k -> entityReferenceSerializer.serialize(k, right.getDocumentReference()))
                        .toArray(String[]::new));
                }
                right.set(USERS_FIELD_RIGHTS_OBJECT, usersProperty.getValue(), context);
            }

            if (null != levels) {
                BaseProperty<?> levelsProperty = levels.fromString("");
                if (null != rule.getRights()) {
                    levelsProperty =
                        levels.fromStringArray(rule.getRights().stream().map(Right::getName).toArray(String[]::new));
                }
                right.set(LEVELS_FIELD_RIGHTS_OBJECT, levelsProperty.getValue(), context);
            }
        }
    }

    /**
     * @return the reference serializer used to serialize the references for users and groups in objects.
     */
    EntityReferenceSerializer<String> getUsersAndGroupsReferenceSerializer()
    {
        return this.entityReferenceSerializer;
    }

    /**
     * @param rule for which the BaseObject will be created
     */
    void addNewRightObjectToDocument(ReadableSecurityRule rule, XWikiDocument doc, EntityReference rightsClass,
        XWikiContext context) throws XWikiException, IllegalArgumentException
    {
        BaseObject object = doc.newXObject(rightsClass, context);
        copyRuleIntoBaseObject(object, rule, context);
    }
}
