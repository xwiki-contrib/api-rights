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

import org.xwiki.model.EntityType;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.internal.XWikiConstants;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Superclass for the test classes for the rights writer, with helper functions and variables.
 * 
 * @version $Id$
 */
public class AbstractRightsWriterTest
{
    /**
     * Helper function to setup mandatory classes on a different subwiki than the main wiki.
     *
     * @param wikiname the wiki name to initialize mandatory classes on
     */
    void initializeMandatoryDocsOnWiki(MockitoOldcore mockedOldCore, String wikiname)
    {
        String oldWikiId = mockedOldCore.getXWikiContext().getWikiId();
        try {
            mockedOldCore.getXWikiContext().setWikiId(wikiname);
            mockedOldCore.getSpyXWiki().initializeMandatoryDocuments(mockedOldCore.getXWikiContext());
        } catch (Exception e) {
            // Dunno what else to do, but definitely I should do something smarter
            e.printStackTrace();
        } finally {
            mockedOldCore.getXWikiContext().setWikiId(oldWikiId);
        }
    }

    /**
     * Helper function to get the non null objects.
     *
     * @param classReference
     * @param document
     * @return
     */
    List<BaseObject> getNonNullObjects(EntityReference classReference, XWikiDocument document)
    {
        return document.getXObjects(classReference).stream().filter(k -> k != null).collect(Collectors.toList());
    }

    /**
     * Helps to assert the state of an object. Since it compares the properties as strings, use only for single values
     * of the tested metadata, since you cannot rely on the order of serialization.
     *
     * @param groups expected groups, as string
     * @param users expected users, as string
     * @param rights expected rights, as string
     * @param allow expected allow as number (1 for allow, 0 for deny)
     * @param testedObj the object to test previous values on
     */
    void assertObject(String groups, String users, String rights, int allow, BaseObject testedObj)
    {
        assertEquals(users, testedObj.getLargeStringValue(XWikiConstants.USERS_FIELD_NAME));
        assertEquals(groups, testedObj.getLargeStringValue(XWikiConstants.GROUPS_FIELD_NAME));
        assertEquals(rights, testedObj.getLargeStringValue(XWikiConstants.LEVELS_FIELD_NAME));
        assertEquals(allow, testedObj.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }

    boolean matchesRule(String groups, String users, String rights, int allow, BaseObject testedObj)
    {
        return groups.equals(testedObj.getLargeStringValue(XWikiConstants.GROUPS_FIELD_NAME))
            && users.equals(testedObj.getLargeStringValue(XWikiConstants.USERS_FIELD_NAME))
            && rights.equals(testedObj.getLargeStringValue(XWikiConstants.LEVELS_FIELD_NAME))
            && allow == testedObj.getIntValue(XWikiConstants.ALLOW_FIELD_NAME);
    }

}
