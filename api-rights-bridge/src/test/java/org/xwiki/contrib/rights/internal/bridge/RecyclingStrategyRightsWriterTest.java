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
import java.util.List;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.contrib.rights.internal.DefaultRightsWriter;
import org.xwiki.contrib.rights.internal.IncrementingObjectNumbersRulesWriter;
import org.xwiki.contrib.rights.internal.RecyclingObjectsRulesWriter;
import org.xwiki.contrib.rights.internal.WritableSecurityRuleImpl;
import org.xwiki.job.event.status.JobProgressManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.XWikiGlobalRightsDocumentInitializer;
import com.xpn.xwiki.internal.mandatory.XWikiRightsDocumentInitializer;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.GroupsClass;
import com.xpn.xwiki.objects.classes.LevelsClass;
import com.xpn.xwiki.objects.classes.UsersClass;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class,
    IncrementingObjectNumbersRulesWriter.class, RecyclingObjectsRulesWriter.class})
public class RecyclingStrategyRightsWriterTest
{
    private static final String XWIKI_SPACE = "XWiki";

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    private static final EntityReference XWIKI_RIGHTS_CLASS =
        new EntityReference("XWikiRights", EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    private static final EntityReference XWIKI_GLOBAL_RIGHTS_CLASS = new EntityReference("XWikiGlobalRights",
        EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

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
        this.oldcore.getSpyXWiki().initializeMandatoryDocuments(this.oldcore.getXWikiContext());
    }

    @Test
    void replaceWithLessRules() throws XWikiException, ComponentLookupException
    {
        SpaceReference spaceReference = new SpaceReference("xwiki", "Space", "Page");
        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumb1 = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Arrays.asList(dumb, dumb1, dumb, dumb1), spaceReference, "recycling");

        DocumentReference spaceWebPreferencesRef = new DocumentReference(XWIKI_WEB_PREFERENCES, spaceReference);
        XWikiDocument spaceWebPreferencesDoc =
            oldcore.getSpyXWiki().getDocument(spaceWebPreferencesRef, oldcore.getXWikiContext());

        int expected = 4;
        assertEquals(expected, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        for (int i = 0; i < expected; ++i) {
            assertEquals(i, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(i).getNumber());
        }

        WritableSecurityRule ruleToCopy = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.PROGRAM, Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(ruleToCopy), spaceReference, "recycling");

        assertEquals(1, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        assertEquals(0, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getNumber());
    }

    @Test
    void replaceWithMoreRules() throws XWikiException, ComponentLookupException
    {
        // copy a rule in the same object & test if it copied all the fields
        DocumentReference documentReference = new DocumentReference("xwiki", "SandBox", "Main");

        DocumentReference user1 = new DocumentReference("xwiki", "XWiki", "Admin");
        DocumentReference user2 = new DocumentReference("xwiki", "test1", "p");
        DocumentReference user3 = new DocumentReference("xwiki", "userSpace", "user");

        DocumentReference group1 = new DocumentReference("xwiki", "XWiki", "group");
        DocumentReference group2 = new DocumentReference("xwiki", "space", "group1");
        DocumentReference group3 = new DocumentReference("xwiki", "MySpace", "group3");
        DocumentReference group4 = new DocumentReference("xwiki", "Something", "group4");

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Arrays.asList(group1, group2),
            Arrays.asList(user1, user2), new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumbRight2 = new WritableSecurityRuleImpl(Arrays.asList(group3, group4),
            Collections.singletonList(user3), new RightSet(Right.VIEW, Right.PROGRAM, Right.EDIT), RuleState.DENY);

        rightsWriter.saveRules(Arrays.asList(dumb, dumbRight2), documentReference, "recycling");

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        int noPersistedObjects = 2;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());

        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }

        rightsWriter.saveRules(Arrays.asList(dumbRight2, dumb, dumbRight2, dumbRight2), documentReference, "recycling");

        noPersistedObjects = 4;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());
        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }
    }

    @Test
    void testReplaceWithSingleRuleOnSpace() throws XWikiException, ComponentLookupException
    {
        replaceWithSingleRule(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES));
    }

    @Test
    void testReplaceWithSingleRuleOnPage() throws XWikiException, ComponentLookupException
    {
        replaceWithSingleRule(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "myPage"));
    }

    private void replaceWithSingleRule(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects) throws XWikiException, ComponentLookupException
    {
        // replace a rule and check that it's in the same object & test if it copied all the fields
        WritableSecurityRule dumbRule = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT, Right.VIEW), RuleState.DENY);

        rightsWriter.saveRules(Collections.singletonList(dumbRule), whereToSaveRules, "recycling");

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertNotNull(document);
        assertEquals(1, document.getXObjects(rightsClassReference).size());
        List<BaseObject> objects = document.getXObjects(rightsClassReference);
        BaseObject right = objects.get(0);

        // before
        assertEquals(Collections.emptyList(), UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.emptyList(), GroupsClass.getListFromString(right.getLargeStringValue("groups")));
        assertEquals(Arrays.asList("view", "edit", "comment"),
            LevelsClass.getListFromString(right.getLargeStringValue("levels")));
        assertEquals(0, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        // replace rule with another rule
        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");
        WritableSecurityRule dumbRule2 = new WritableSecurityRuleImpl(Collections.singletonList(adminUserDocRef),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(dumbRule2), whereToSaveRules, "recycling");

        document = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertNotNull(document);
        assertEquals(1, document.getXObjects(rightsClassReference).size());
        objects = document.getXObjects(rightsClassReference);
        right = objects.get(0);

        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            GroupsClass.getListFromString(right.getLargeStringValue("groups")));
        assertEquals(Collections.singletonList("view"),
            LevelsClass.getListFromString(right.getLargeStringValue("levels")));
        assertEquals(1, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }
}
