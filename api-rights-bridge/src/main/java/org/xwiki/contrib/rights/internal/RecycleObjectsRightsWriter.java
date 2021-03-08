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
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.ReadableSecurityRule;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * @version $Id$
 */
@Component
@Singleton
@Named("default")
public class RecycleObjectsRightsWriter extends AbstractRightsWriter
{
    /**
     * Saves the passed rules on the given reference. The passed rules replace whatever other rules were already in
     * place on the passed reference, "What you send is what you get". If you need to add to the existing rules of the
     * reference, use the {@link RightsReader} API to read the existing rules, then turn them into writable ones using
     * {@link RightsWriter#createRules(List)}, add a new rule and then persist them using this function.
     * <p>
     * TODO: write about recycling objects.
     *
     * @param rules the new rules to set for the passed reference. They will replace whatever existing rules are
     *     already there. Writable rules can also be passed, since they are readable as well.
     * @param reference the reference to update rules on. Can be a document or a space or a wiki.
     */
    @Override public void saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
        throws XWikiException, UnsupportedOperationException
    {
        if (null != rules && null != reference) {
            DocumentReference documentReference;
            switch (reference.getType()) {
                case WIKI:
                    documentReference = new DocumentReference(XWIKI_PREFERENCES,
                        new SpaceReference(XWIKI_SPACE, new WikiReference(reference)));
                    addRightsByRecyclingObjects(rules, documentReference, XWIKI_GLOBAL_RIGHTS_CLASS);
                    break;
                case SPACE:
                    documentReference = new DocumentReference(XWIKI_WEB_PREFERENCES, new SpaceReference(reference));
                    addRightsByRecyclingObjects(rules, documentReference, XWIKI_GLOBAL_RIGHTS_CLASS);
                    break;
                case DOCUMENT:
                    // The current reference corresponds to a terminal page.
                    documentReference = new DocumentReference(reference);
                    addRightsByRecyclingObjects(rules, documentReference, XWIKI_RIGHTS_CLASS);
                    break;
                default:
                    throw new UnsupportedOperationException("Could not set rights for the given reference.");
            }
        }
    }

    /**
     * @param rules for which Right BaseObjects will be created and added to the <code>document</code>
     * @param reference
     * @param classReference {@link AbstractRightsWriter#XWIKI_GLOBAL_RIGHTS_CLASS} or {@link
     *     AbstractRightsWriter#XWIKI_GLOBAL_RIGHTS_CLASS}, depending on the {@link EntityType} of the
     *     <code>document</code>
     * @throws XWikiException
     */
    private void addRightsByRecyclingObjects(List<ReadableSecurityRule> rules, EntityReference reference,
        EntityReference classReference) throws XWikiException
    {
        XWikiDocument document = getXWiki().getDocument(reference, getXContext());
        List<BaseObject> storedObjects = document.getXObjects(classReference);
        if (rules.size() > storedObjects.size()) {
            for (int i = 0; i < storedObjects.size(); ++i) {
                copyRuleIntoBaseObject(storedObjects.get(i), rules.get(i));
            }
            for (int i = storedObjects.size(); i < rules.size(); ++i) {
                // Create new objects in the document.
                addRightObjectToDocument(rules.get(i), document, classReference);
            }
        } else {
            for (int i = 0; i < rules.size(); ++i) {
                copyRuleIntoBaseObject(storedObjects.get(i), rules.get(i));
            }
            while (rules.size() != storedObjects.size()) {
                storedObjects.remove(storedObjects.size() - 1);
            }
        }

        // In the end, save the document
        getXWiki().saveDocument(document, getXContext());
    }
}
