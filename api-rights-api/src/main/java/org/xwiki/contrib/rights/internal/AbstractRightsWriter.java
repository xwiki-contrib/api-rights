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

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.objects.classes.PropertyClass;

/**
 * @version $Id$
 */
public abstract class AbstractRightsWriter implements RightsWriter
{
    protected static final String USERS_FIELD_RIGHTS_OBJECT = "users";

    protected static final String GROUPS_FIELD_RIGHTS_OBJECT = "groups";

    protected static final String LEVELS_FIELD_RIGHTS_OBJECT = "levels";

    protected static final String XWIKI_SPACE = "XWiki";

    protected static final EntityReference XWIKI_RIGHTS_CLASS =
        new EntityReference("XWikiRights", EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    protected static final EntityReference XWIKI_GLOBAL_RIGHTS_CLASS = new EntityReference("XWikiGlobalRights",
        EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    protected static final String XWIKI_PREFERENCES = "XWikiPreferences";

    protected static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    @Inject
    protected Provider<XWikiContext> xcontextProvider;

    @Inject
    @Named("compactwiki")
    protected EntityReferenceSerializer<String> entityReferenceSerializer;

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule()
     */
    @Override
    public WritableSecurityRule createRule()
    {
        return new WritableSecurityRuleImpl();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule(java.util.List, java.util.List, java.util.List,
     *     org.xwiki.security.authorization.RuleState)
     */
    @Override
    public WritableSecurityRule createRule(List<DocumentReference> groups, List<DocumentReference> users,
        List<Right> rights, RuleState ruleState)
    {
        return new WritableSecurityRuleImpl(groups, users, new RightSet(rights), ruleState);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRule(ReadableSecurityRule)
     */
    @Override
    public WritableSecurityRule createRule(ReadableSecurityRule ruleToCopy)
    {
        return new WritableSecurityRuleImpl(ruleToCopy.getGroups(), ruleToCopy.getUsers(), ruleToCopy.getRights(),
            ruleToCopy.getState());
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsWriter#createRules(java.util.List)
     */
    @Override
    public List<WritableSecurityRule> createRules(List<ReadableSecurityRule> rulesToCopy)
    {
        List<WritableSecurityRule> writableRules = new ArrayList<>();
        for (ReadableSecurityRule rule : rulesToCopy) {
            writableRules.add(new WritableSecurityRuleImpl(rule.getGroups(), rule.getUsers(), rule.getRights(),
                rule.getState()));
        }
        return writableRules;
    }

    /**
     * Translates a {@link ReadableSecurityRule} into a {@link BaseObject}.
     * <p>
     * It's the caller responsibility to call this on a valid right object (depending on what's the desired behavior,
     * the <code>right</code>'s XClass should be, but not limited to {@link #XWIKI_RIGHTS_CLASS} or {@link
     * #XWIKI_GLOBAL_RIGHTS_CLASS}.
     *
     * @param right the BaseObject to which the properties of the <code>rule</code> will be copied to
     * @param rule
     */
    protected void copyRuleIntoBaseObject(BaseObject right, ReadableSecurityRule rule)
    {
        if (null != right) {
            if (null != rule.getState()) {
                right.setIntValue(XWikiConstants.ALLOW_FIELD_NAME,
                    rule.getState().getValue() == RuleState.DENY.getValue() ? 0 : 1);
            }
            PropertyClass groups = (PropertyClass) right.getXClass(getXContext()).get(GROUPS_FIELD_RIGHTS_OBJECT);
            PropertyClass users = (PropertyClass) right.getXClass(getXContext()).get(USERS_FIELD_RIGHTS_OBJECT);
            PropertyClass levels = (PropertyClass) right.getXClass(getXContext()).get(LEVELS_FIELD_RIGHTS_OBJECT);
            if (null != groups) {
                BaseProperty<?> groupsProperty = groups.fromStringArray(
                    rule.getGroups().stream()
                        .map(entityReferenceSerializer::serialize)
                        .toArray(String[]::new)
                );
                right.set(GROUPS_FIELD_RIGHTS_OBJECT, groupsProperty.getValue(), getXContext());
            }

            if (null != users) {
                BaseProperty<?> usersProperty = users.fromStringArray(
                    rule.getUsers().stream()
                        .map(entityReferenceSerializer::serialize)
                        .toArray(String[]::new)
                );
                right.set(USERS_FIELD_RIGHTS_OBJECT, usersProperty.getValue(), getXContext());
            }

            if (null != levels) {
                BaseProperty<?> levelsProperty = levels.fromStringArray(
                    rule.getRights().stream()
                        .map(Right::getName)
                        .toArray(String[]::new)
                );
                right.set(LEVELS_FIELD_RIGHTS_OBJECT, levelsProperty.getValue(), getXContext());
            }
        }
    }

    /**
     * @param rule for which the BaseObject will be created
     */
    protected void addRightObjectToDocument(ReadableSecurityRule rule, XWikiDocument doc, EntityReference rightsClass)
        throws XWikiException, IllegalArgumentException
    {
        BaseObject object = doc.newXObject(rightsClass, getXContext());
        copyRuleIntoBaseObject(object, rule);
    }

    /**
     * @param rules containing the actual security rules that will be translated into BaseObjects
     * @param reference the reference on which the objects will be added
     * @param isGlobal if true, the created BaseObjects will be of type XWikiGlobalRights. Else, XWikiRights objects
     *     will be created.
     */
    protected void addRulesToDocumentReference(List<ReadableSecurityRule> rules, DocumentReference reference,
        boolean isGlobal) throws XWikiException
    {
        XWikiDocument doc = getXContext().getWiki().getDocument(reference, getXContext());
        EntityReference rightsClass;
        if (isGlobal) {
            rightsClass = XWIKI_GLOBAL_RIGHTS_CLASS;
        } else {
            rightsClass = XWIKI_RIGHTS_CLASS;
        }
        for (ReadableSecurityRule rule : rules) {
            addRightObjectToDocument(rule, doc, rightsClass);
        }
        // All the objects were added, save the document. Either all rules were saved, either none of them.
        getXContext().getWiki().saveDocument(doc, getXContext());
    }

    /**
     * @return the xcontext
     */
    protected XWikiContext getXContext()
    {
        return xcontextProvider.get();
    }

    /**
     * @return the XWiki object
     */
    protected XWiki getXWiki()
    {
        return getXContext().getWiki();
    }
}
