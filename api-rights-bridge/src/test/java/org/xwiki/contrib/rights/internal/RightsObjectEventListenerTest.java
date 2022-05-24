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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.RightUpdatedEvent;
import org.xwiki.contrib.rights.RulesObjectWriter;
import org.xwiki.contrib.rights.SecurityRuleAbacus;
import org.xwiki.contrib.rights.SecurityRuleDiff;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.observation.event.Event;
import org.xwiki.observation.remote.RemoteObservationManagerContext;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.XObjectEvent;
import com.xpn.xwiki.internal.event.XObjectUpdatedEvent;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseObjectReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link RightObjectEventListener}.
 *
 * @version $Id$
 */
@ComponentTest
class RightsObjectEventListenerTest
{
    @InjectMockComponents
    private RightObjectEventListener listener;

    @MockComponent
    private ObservationManager observationManager;

    @MockComponent
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @MockComponent
    private SecurityReferenceFactory securityReferenceFactory;

    @MockComponent
    private SecurityRuleAbacus securityRuleAbacus;

    @MockComponent
    private RemoteObservationManagerContext remoteObservationManagerContext;

    private XWikiSecurityRule mockRightObject(BaseObject baseObjectMock, RuleState state, List<Right> rights,
        Pair<String, List<DocumentReference>> userReferences,
        Pair<String, List<DocumentReference>> groupReferences)
    {
        if (baseObjectMock != null) {
            int allowValue = (state == RuleState.ALLOW) ? 1 : 0;
            when(baseObjectMock.getIntValue(XWikiConstants.ALLOW_FIELD_NAME)).thenReturn(allowValue);

            when(baseObjectMock.getStringValue(XWikiConstants.LEVELS_FIELD_NAME)).thenReturn(StringUtils.join(
                rights.stream().map(Right::getName).collect(Collectors.toList()), ","));
            when(baseObjectMock.getStringValue(XWikiConstants.USERS_FIELD_NAME)).thenReturn(userReferences.getLeft());
            when(baseObjectMock.getStringValue(XWikiConstants.GROUPS_FIELD_NAME)).thenReturn(groupReferences.getLeft());
        }

        return
            new XWikiSecurityRule(new HashSet<>(rights), state, userReferences.getRight(), groupReferences.getRight());
    }

    @Test
    void onRemoteEvent()
    {
        when(this.remoteObservationManagerContext.isRemoteState()).thenReturn(true);
        this.listener.onEvent(mock(Event.class), null, null);
        verifyNoInteractions(this.securityRuleAbacus);
    }

    @Test
    void onRightUpdatedEventFromPage()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference("SomePage",
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // update event: the second obj have been updated, the list remains of same size
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        BaseObject updatedRightObj2 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, updatedRightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // updatedRightObj2: Deny - Edit,Script - User Foo
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(updatedRightObj2, RuleState.DENY, Arrays.asList(Right.EDIT, Right.SCRIPT),
                Pair.of("Foo", Collections.singletonList(userFooRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(null, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);
        when(this.securityReferenceFactory.newEntityReference(sourceDocReference))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }

    @Test
    void onRightUpdatedEventFromSpace()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference(RulesObjectWriter.XWIKI_WEB_PREFERENCES,
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // added event: the third obj have been added
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList()))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(null, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);

        // it's a standard right updated on the WebPreferences page, so we trigger the event directly from the page
        // itself not from the space: we'd trigger it from the space if the right change were about a global right.
        when(this.securityReferenceFactory.newEntityReference(sourceDocReference))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }

    @Test
    void onRightUpdatedEventFromWiki()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference(RulesObjectWriter.XWIKI_PREFERENCES,
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // delete event: the first obj have been removed
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // updatedRightObj2: Deny - Edit,Script - User Foo
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(null, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);

        // it's a standard right updated on the XWikiPreferences page, so we trigger the event directly from the page
        // itself not from the wiki: we'd trigger it from the wiki if the right change were about a global right.
        when(this.securityReferenceFactory.newEntityReference(sourceDocReference))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }

    @Test
    void onGlobalRightUpdatedEventFromPage()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference("SomePage",
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // update event: the second obj have been updated, the list remains of same size
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        BaseObject updatedRightObj2 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, updatedRightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // updatedRightObj2: Deny - Edit,Script - User Foo
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(updatedRightObj2, RuleState.DENY, Arrays.asList(Right.EDIT, Right.SCRIPT),
                Pair.of("Foo", Collections.singletonList(userFooRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(null, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);
        when(this.securityReferenceFactory.newEntityReference(sourceDocReference))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }

    @Test
    void onGlobalRightUpdatedEventFromSpace()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference(RulesObjectWriter.XWIKI_WEB_PREFERENCES,
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // added event: the third obj have been added
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList()))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(null, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);

        when(this.securityReferenceFactory.newEntityReference(new SpaceReference("SomeSpace", wikiReference)))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }

    @Test
    void onGlobalRightUpdatedEventFromWiki()
    {
        XObjectEvent event = mock(XObjectUpdatedEvent.class);
        XWikiDocument source = mock(XWikiDocument.class);
        BaseObjectReference baseObjectReference = mock(BaseObjectReference.class);

        when(event.getReference()).thenReturn(baseObjectReference);
        DocumentReference rightXClassReference = mock(DocumentReference.class);
        when(baseObjectReference.getXClassReference()).thenReturn(rightXClassReference);
        when(rightXClassReference.getLocalDocumentReference())
            .thenReturn((LocalDocumentReference) DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS);

        WikiReference wikiReference = new WikiReference("foo");
        DocumentReference sourceDocReference = new DocumentReference(RulesObjectWriter.XWIKI_PREFERENCES,
            new SpaceReference("SomeSpace", wikiReference));
        when(baseObjectReference.getDocumentReference()).thenReturn(sourceDocReference);

        XWikiDocument previousDoc = mock(XWikiDocument.class);
        when(source.getOriginalDocument()).thenReturn(previousDoc);
        when(source.getDocumentReference()).thenReturn(sourceDocReference);
        when(previousDoc.getDocumentReference()).thenReturn(sourceDocReference);

        // delete event: the first obj have been removed
        BaseObject rightObj1 = mock(BaseObject.class);
        BaseObject rightObj2 = mock(BaseObject.class);
        BaseObject rightObj3 = mock(BaseObject.class);

        when(previousDoc.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj1, rightObj2, rightObj3));
        when(source.getXObjects(DefaultRightsWriter.XWIKI_GLOBAL_RIGHTS_CLASS))
            .thenReturn(Arrays.asList(rightObj2, rightObj3));

        // rightObj1: Allow - View & Edit - Group groupA, User Buz
        // rightObj2: Deny - Script - User Foo,Bar
        // updatedRightObj2: Deny - Edit,Script - User Foo
        // rightObj3: Allow - Admin - Group groupB,groupC

        DocumentReference groupARef = mock(DocumentReference.class);
        DocumentReference groupBRef = mock(DocumentReference.class);
        DocumentReference groupCRef = mock(DocumentReference.class);

        DocumentReference userFooRef = mock(DocumentReference.class);
        DocumentReference userBarRef = mock(DocumentReference.class);
        DocumentReference userBuzRef = mock(DocumentReference.class);

        when(this.documentReferenceResolver.resolve("groupA", wikiReference)).thenReturn(groupARef);
        when(this.documentReferenceResolver.resolve("groupB", wikiReference)).thenReturn(groupBRef);
        when(this.documentReferenceResolver.resolve("groupC", wikiReference)).thenReturn(groupCRef);

        when(this.documentReferenceResolver.resolve("Foo", wikiReference)).thenReturn(userFooRef);
        when(this.documentReferenceResolver.resolve("Bar", wikiReference)).thenReturn(userBarRef);
        when(this.documentReferenceResolver.resolve("Buz", wikiReference)).thenReturn(userBuzRef);

        List<ReadableSecurityRule> expectedPreviousRules = Arrays.asList(
            mockRightObject(rightObj1, RuleState.ALLOW, Arrays.asList(Right.VIEW, Right.EDIT),
                Pair.of("Buz", Collections.singletonList(userBuzRef)),
                Pair.of("groupA", Collections.singletonList(groupARef))),
            mockRightObject(rightObj2, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(rightObj3, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        List<ReadableSecurityRule> expectedCurrentRules = Arrays.asList(
            mockRightObject(null, RuleState.DENY, Collections.singletonList(Right.SCRIPT),
                Pair.of("Foo,Bar", Arrays.asList(userFooRef, userBarRef)),
                Pair.of("", Collections.emptyList())),
            mockRightObject(null, RuleState.ALLOW, Collections.singletonList(Right.ADMIN),
                Pair.of("", Collections.emptyList()),
                Pair.of("groupB,groupC", Arrays.asList(groupBRef, groupCRef)))
        );

        SecurityReference expectedSecurityReference = mock(SecurityReference.class);

        when(this.securityReferenceFactory.newEntityReference(wikiReference))
            .thenReturn(expectedSecurityReference);

        List<SecurityRuleDiff> diffList = mock(List.class);
        when(this.securityRuleAbacus.computeRuleDiff(expectedPreviousRules, expectedCurrentRules))
            .thenReturn(diffList);
        this.listener.onEvent(event, source, null);
        verify(this.securityRuleAbacus).computeRuleDiff(expectedPreviousRules, expectedCurrentRules);
        verify(this.observationManager)
            .notify(any(RightUpdatedEvent.class), eq(expectedSecurityReference), eq(diffList));
    }
}
