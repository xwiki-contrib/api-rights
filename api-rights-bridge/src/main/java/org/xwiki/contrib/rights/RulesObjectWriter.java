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
package org.xwiki.contrib.rights;

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Service to persist rights objects in a document.
 * 
 * @version $Id$
 */
@Role
public interface RulesObjectWriter
{
    /**
     * Persists the passed rules as objects on the passed document, according to the strategy specific to each
     * implementation.
     * 
     * @param rules the rules to persist
     * @param d the document to persist them on (the actual document, no logic of WebPreferences needs to be done)
     * @param rightsClass the class of the rights objects to be saved
     * @param context the XWikiContext of this save
     * @throws XWikiException in case anything goes wrong
     */
    void persistRulesToObjects(List<ReadableSecurityRule> rules, XWikiDocument d, EntityReference rightsClass,
        XWikiContext context) throws XWikiException;
}
