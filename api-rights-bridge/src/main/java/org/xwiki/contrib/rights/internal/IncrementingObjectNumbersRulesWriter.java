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
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * @version $Id$
 */
@Component
@Singleton
@Named("incrementingnumbers")
public class IncrementingObjectNumbersRulesWriter extends AbstractRulesObjectWriter
{
    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.contrib.rights.RulesObjectWriter#persistRulesToObjects(java.util.List,
     *      com.xpn.xwiki.doc.XWikiDocument, org.xwiki.model.reference.EntityReference, com.xpn.xwiki.XWikiContext)
     */
    @Override
    public void persistRulesToObjects(List<ReadableSecurityRule> rules, XWikiDocument d, EntityReference rightsClass,
        XWikiContext context) throws XWikiException
    {
        d.removeXObjects(rightsClass);
        for (ReadableSecurityRule rule : rules) {
            addNewRightObjectToDocument(rule, d, rightsClass, context);
        }
    }
}
