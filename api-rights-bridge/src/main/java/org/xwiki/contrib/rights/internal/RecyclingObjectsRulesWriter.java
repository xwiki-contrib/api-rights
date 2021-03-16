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
import java.util.stream.Collectors;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * @version $Id$
 */
@Component
@Singleton
@Named("recycling")
public class RecyclingObjectsRulesWriter extends AbstractRulesObjectWriter
{

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.contrib.rights.RulesObjectWriter#persistRulesToObjects(java.util.List,
     *      com.xpn.xwiki.doc.XWikiDocument, org.xwiki.model.reference.EntityReference)
     */
    @Override
    public void persistRulesToObjects(List<ReadableSecurityRule> rules, XWikiDocument document,
        EntityReference classReference, XWikiContext context) throws XWikiException
    {
        // TODO: the parameter type should be DocumentReference
        List<BaseObject> storedObjects = document.getXObjects(classReference);

        // collect all non null BaseObjects that can be recycled so that we recycle them
        List<BaseObject> recyclableObjects = storedObjects.stream().filter(k -> k != null).collect(Collectors.toList());

        if (rules.size() > recyclableObjects.size()) {
            // more rules than recyclable objects -> recycle the objects and then create new ones until all rules are
            // persisted
            for (int i = 0; i < recyclableObjects.size(); ++i) {
                copyRuleIntoBaseObject(recyclableObjects.get(i), rules.get(i), context);
            }
            for (int i = recyclableObjects.size(); i < rules.size(); ++i) {
                // Create new objects in the document.
                addNewRightObjectToDocument(rules.get(i), document, classReference, context);
            }
        } else {
            // less or same number of rules to save than recyclable objects: fill the recyclable objects and remove the
            // rest of recyclableObjects
            for (int i = 0; i < rules.size(); ++i) {
                copyRuleIntoBaseObject(recyclableObjects.get(i), rules.get(i), context);
            }

            for (int i = rules.size(); i < recyclableObjects.size(); ++i) {
                document.removeXObject(recyclableObjects.get(i));
            }
        }
    }
}
