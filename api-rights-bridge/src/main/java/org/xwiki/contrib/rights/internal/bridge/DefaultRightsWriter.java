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
package org.xwiki.contrib.rights.internal.bridge;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.internal.AbstractRightsWriter;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
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
@Component
@Singleton
public class DefaultRightsWriter extends AbstractRightsWriter
{
    private static final String USERS_FIELD_RIGHTS_OBJECT = "users";

    private static final String GROUPS_FIELD_RIGHTS_OBJECT = "groups";

    private static final String LEVELS_FIELD_RIGHTS_OBJECT = "levels";

    private static final String XWIKI_SPACE = "XWiki";

    private static final EntityReference XWIKI_RIGHTS_CLASS =
        new EntityReference("XWikiRights", EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    private static final EntityReference XWIKI_GLOBAL_RIGHTS_CLASS = new EntityReference("XWikiGlobalRights",
        EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    private static final String XWIKI_PREFERENCES = "XWikiPreferences";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    /**
     * One rule will correspond to one right object.
     *
     * @see org.xwiki.contrib.rights.RightsWriter#saveRules(java.util.List, org.xwiki.model.reference.EntityReference)
     */
    @Override
    public void saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
        throws XWikiException, UnsupportedOperationException
    {
        // By deleting the objects, the object number will continue from the number of the deleted object.
        if (null != rules && null != reference) {
            DocumentReference documentReference;
            switch (reference.getType()) {
                case WIKI:
                    documentReference = new DocumentReference(XWIKI_PREFERENCES, new SpaceReference(XWIKI_SPACE,
                        new WikiReference(reference)));
                    clearRightsOnPage(documentReference, true);
                    addRulesAsObjects(rules, documentReference, true);
                    break;
                case SPACE:
                    documentReference = new DocumentReference(XWIKI_WEB_PREFERENCES, new SpaceReference(reference));
                    clearRightsOnPage(documentReference, true);
                    addRulesAsObjects(rules, documentReference, true);
                    break;
                case DOCUMENT:
                    // The current reference corresponds to a terminal page.
                    documentReference = new DocumentReference(reference);
                    clearRightsOnPage(documentReference, false);
                    addRulesAsObjects(rules, documentReference, false);
                    break;
                default:
                    throw new UnsupportedOperationException("Could not set rights for the given reference.");
            }
        }
    }

    /**
     * @return the xcontext
     */
    private XWikiContext getXContext()
    {
        return xcontextProvider.get();
    }

    /**
     * @return the XWiki object
     */
    private XWiki getXWiki()
    {
        return getXContext().getWiki();
    }

    /**
     * @param rules containing the actual security rules that will be translated into BaseObjects
     * @param reference the reference on which the objects will be added
     * @param isGlobal if true, the created BaseObjects will be of type XWikiGlobalRights. Else, XWikiRights objects
     *     will be created.
     */
    private void addRulesAsObjects(List<ReadableSecurityRule> rules, DocumentReference reference, boolean isGlobal)
        throws XWikiException
    {
        XWikiDocument doc = getXWiki().getDocument(reference, getXContext());
        EntityReference rightsClass;
        if (isGlobal) {
            rightsClass = XWIKI_GLOBAL_RIGHTS_CLASS;
        } else {
            rightsClass = XWIKI_RIGHTS_CLASS;
        }
        for (ReadableSecurityRule rule : rules) {
            addRightObjectToDocument(rule, doc, rightsClass, getXContext());
        }
        // All the objects were added, save the document. Either all rules were saved, either none of them.
        getXWiki().saveDocument(doc, getXContext());
    }

    /**
     * @param rule for which the BaseObject will be created
     */
    private void addRightObjectToDocument(ReadableSecurityRule rule, XWikiDocument doc, EntityReference rightsClass,
        XWikiContext context) throws XWikiException
    {
        BaseObject object = doc.newXObject(rightsClass, context);
        if (null != rule.getState()) {
            // TODO: this checking won't be anymore necessary after deciding if the state of the rule can be or
            //  not a null.
            object.setIntValue(XWikiConstants.ALLOW_FIELD_NAME,
                rule.getState().getValue() == RuleState.DENY.getValue() ? 0 : 1);
        }
        PropertyClass groups = (PropertyClass) object.getXClass(getXContext()).get(GROUPS_FIELD_RIGHTS_OBJECT);
        PropertyClass users = (PropertyClass) object.getXClass(getXContext()).get(USERS_FIELD_RIGHTS_OBJECT);
        PropertyClass levels = (PropertyClass) object.getXClass(getXContext()).get(LEVELS_FIELD_RIGHTS_OBJECT);
        BaseProperty<?> groupsProperty = groups.fromStringArray(
            rule.getGroups().stream()
                .map(k -> entityReferenceSerializer.serialize(k))
                .toArray(String[]::new)
        );

        BaseProperty<?> usersProperty = users.fromStringArray(
            rule.getUsers().stream()
                .map(k -> entityReferenceSerializer.serialize(k))
                .toArray(String[]::new)
        );

        BaseProperty<?> levelsProperty = levels.fromStringArray(
            rule.getRights().stream()
                .map(Right::getName)
                .toArray(String[]::new)
        );

        object.set(GROUPS_FIELD_RIGHTS_OBJECT, groupsProperty.getValue(), getXContext());
        object.set(USERS_FIELD_RIGHTS_OBJECT, usersProperty.getValue(), getXContext());
        object.set(LEVELS_FIELD_RIGHTS_OBJECT, levelsProperty.getValue(), getXContext());
    }

    private void clearRightsOnPage(DocumentReference reference, boolean areGlobalRights) throws XWikiException
    {
        if (areGlobalRights) {
            getXWiki().getDocument(reference, getXContext()).removeXObjects(XWIKI_GLOBAL_RIGHTS_CLASS);
        } else {
            getXWiki().getDocument(reference, getXContext()).removeXObjects(XWIKI_RIGHTS_CLASS);
        }
    }
}
