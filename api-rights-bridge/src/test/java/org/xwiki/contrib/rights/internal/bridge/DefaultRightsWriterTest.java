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

import java.util.Arrays;
import java.util.Collections;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.contrib.rights.internal.WritableSecurityRuleImpl;
import org.xwiki.job.event.status.JobProgressManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.XWikiGlobalRightsDocumentInitializer;
import com.xpn.xwiki.internal.mandatory.XWikiRightsDocumentInitializer;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class})
class DefaultRightsWriterTest
{
    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private ObservationManager obsManager;

    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private JobProgressManager jobsProgressManager;

    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private ContextualLocalizationManager localizationManager;

    /*
     * Mocked for the initializers, they use the sheet binder to check if some specific sheet needs to be bound to the
     * classes, we don't care so we put an empty mock.
     */
    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @InjectMockComponents
    private DefaultRightsWriter rightsWriter;

    @BeforeEach
    void setUp()
    {
    }

    @Test
    void saveRulesOnObject() throws XWikiException
    {
        EntityReference objRef = new ObjectReference("XWiki.XWikiComments", new DocumentReference("xwiki", "S", "P"));

        Exception exc = assertThrows(UnsupportedOperationException.class, () -> {
            // Content throwing exception here
            this.rightsWriter.saveRules(Collections.emptyList(), objRef);
        });

        assertEquals("Could not set rights for the given reference.", exc.getMessage());
    }

    @Test
    void saveViewRuleOnDocument() throws Exception
    {
        // this needs to be moved in some "before", I think, but it's not clear if it's a "before all" or "before each"
        this.oldcore.getSpyXWiki().initializeMandatoryDocuments(this.oldcore.getXWikiContext());
        // prepare a document to put rights on
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document
        WritableSecurityRule rule = new WritableSecurityRuleImpl();
        rule.setGroups(Collections.emptyList());
        rule.setUsers(Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdmin")));
        rule.setState(RuleState.ALLOW);
        rule.setRights(Arrays.asList(Right.VIEW));

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        Document resultDocEasyAPI = new Document(resultDoc, this.oldcore.getXWikiContext());
        // check that there is an object set
        assertEquals(1, resultDocEasyAPI.getxWikiObjects().size());
        // check that the object is of the good class and has number 0
        assertEquals(1, resultDocEasyAPI.getObjects("XWiki.XWikiRights").size());
        assertEquals(0, resultDocEasyAPI.getObject("XWiki.XWikiRights").getNumber());
    }
}
