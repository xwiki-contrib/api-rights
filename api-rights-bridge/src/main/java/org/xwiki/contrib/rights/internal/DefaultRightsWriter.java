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

import java.util.List;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
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
@Component
@Singleton
@Named("preserveObjectNumber")
public class DefaultRightsWriter extends AbstractRightsWriter
{
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
                    addRulesToDocumentReference(rules, documentReference, true);
                    break;
                case SPACE:
                    documentReference = new DocumentReference(XWIKI_WEB_PREFERENCES, new SpaceReference(reference));
                    clearRightsOnPage(documentReference, true);
                    addRulesToDocumentReference(rules, documentReference, true);
                    break;
                case DOCUMENT:
                    // The current reference corresponds to a terminal page.
                    documentReference = new DocumentReference(reference);
                    clearRightsOnPage(documentReference, false);
                    addRulesToDocumentReference(rules, documentReference, false);
                    break;
                default:
                    throw new UnsupportedOperationException("Could not set rights for the given reference.");
            }
        }
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
    public void copyRuleIntoBaseObject(BaseObject right, ReadableSecurityRule rule)
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
                        .map(k -> entityReferenceSerializer.serialize(k, right.getDocumentReference()))
                        .toArray(String[]::new)
                );
                right.set(GROUPS_FIELD_RIGHTS_OBJECT, groupsProperty.getValue(), getXContext());
            }

            if (null != users) {
                BaseProperty<?> usersProperty = users.fromStringArray(
                    rule.getUsers().stream()
                        .map(k -> entityReferenceSerializer.serialize(k, right.getDocumentReference()))
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
     * @param rules for which Right BaseObjects will be created and added to the <code>document</code>
     * @param document where the <code>rules</code> are saved
     * @param classReference {@link #XWIKI_GLOBAL_RIGHTS_CLASS} or {@link #XWIKI_RIGHTS_CLASS}, depending on the
     *     {@link EntityType} of the <code>document</code>
     * @throws XWikiException
     */
    public void addRightsByRecyclingObjects(List<ReadableSecurityRule> rules, XWikiDocument document,
        EntityReference classReference) throws XWikiException
    {
        // TODO: the parameter type should be DocumentReference
        List<BaseObject> storedObjects = document.getXObjects(classReference);
        if (rules.size() > storedObjects.size()) {
            for (int i = 0; i < storedObjects.size(); ++i) {
                copyRuleIntoBaseObject(storedObjects.get(i), rules.get(i));
            }
            for (int i = storedObjects.size(); i < rules.size(); ++i) {
                // Create new objects in the document.
                addRightObjectToDocument(rules.get(i), document, classReference, getXContext());
            }
        } else {
            for (int i = 0; i < rules.size(); ++i) {
                copyRuleIntoBaseObject(storedObjects.get(i), rules.get(i));
            }
            while (rules.size() != storedObjects.size()) {
                storedObjects.remove(storedObjects.size() - 1);
            }
        }

        document.setAuthorReference(getXContext().getUserReference());
        // In the end, save the document
        getXWiki().saveDocument(document, getXContext());
    }

//    /**
//     * @param rules containing the actual security rules that will be translated into BaseObjects
//     * @param reference the reference on which the objects will be added
//     * @param isGlobal if true, the created BaseObjects will be of type XWikiGlobalRights. Else, XWikiRights objects
//     *     will be created.
//     */
//    private void addRulesToDocumentReference(List<ReadableSecurityRule> rules, DocumentReference reference,
//        boolean isGlobal)
//        throws XWikiException
//    {
//        XWikiDocument doc = getXWiki().getDocument(reference, getXContext());
//        EntityReference rightsClass;
//        if (isGlobal) {
//            rightsClass = XWIKI_GLOBAL_RIGHTS_CLASS;
//        } else {
//            rightsClass = XWIKI_RIGHTS_CLASS;
//        }
//        for (ReadableSecurityRule rule : rules) {
//            addRightObjectToDocument(rule, doc, rightsClass, getXContext());
//        }
//        doc.setAuthorReference(getXContext().getUserReference());
//        // All the objects were added, save the document. Either all rules were saved, either none of them.
//        getXWiki().saveDocument(doc, getXContext());
//    }

    /**
     * @param rule for which the BaseObject will be created
     */
    private void addRightObjectToDocument(ReadableSecurityRule rule, XWikiDocument doc, EntityReference rightsClass,
        XWikiContext context) throws XWikiException, IllegalArgumentException
    {
        BaseObject object = doc.newXObject(rightsClass, context);
        copyRuleIntoBaseObject(object, rule);
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
