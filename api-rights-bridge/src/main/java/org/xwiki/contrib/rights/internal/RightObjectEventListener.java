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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.RightUpdatedEvent;
import org.xwiki.contrib.rights.RulesObjectWriter;
import org.xwiki.contrib.rights.SecurityRuleAbacus;
import org.xwiki.contrib.rights.SecurityRuleDiff;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.observation.event.Event;
import org.xwiki.refactoring.internal.listener.AbstractDocumentEventListener;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.SecurityReferenceFactory;
import org.xwiki.security.authorization.ReadableSecurityRule;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.XObjectEvent;
import com.xpn.xwiki.internal.mandatory.XWikiGlobalRightsDocumentInitializer;
import com.xpn.xwiki.internal.mandatory.XWikiRightsDocumentInitializer;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * Component responsible to listen for the xobject events related to XWikiRights and XWikiGlobalRights xclass and to
 * trigger the {@link org.xwiki.contrib.rights.RightUpdatedEvent}.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Named(RightObjectEventListener.NAME)
@Singleton
public class RightObjectEventListener extends AbstractDocumentEventListener
{
    static final String NAME = "org.xwiki.contrib.rights.internal.RightObjectEventListener";

    @Inject
    private ObservationManager observationManager;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private SecurityReferenceFactory securityReferenceFactory;

    @Inject
    private SecurityRuleAbacus securityRuleAbacus;

    /**
     * Default constructor.
     */
    public RightObjectEventListener()
    {
        super(NAME,
            Stream.of(
                    BaseObjectReference.anyEvents(XWikiRightsDocumentInitializer.CLASS_REFERENCE_STRING),
                    BaseObjectReference.anyEvents(XWikiGlobalRightsDocumentInitializer.CLASS_REFERENCE_STRING))
                .flatMap(List::stream).toArray(XObjectEvent[]::new));
    }

    @Override
    public void processLocalEvent(Event event, Object source, Object data)
    {
        XObjectEvent xObjectEvent = (XObjectEvent) event;
        EntityReference reference = xObjectEvent.getReference();
        BaseObjectReference baseObjectReference = (BaseObjectReference) reference;
        DocumentReference xClassReference = baseObjectReference.getXClassReference();
        boolean isGlobalRight =
            xClassReference.getLocalDocumentReference().equals(XWikiGlobalRightsDocumentInitializer.CLASS_REFERENCE);
        DocumentReference sourceDocumentReference = baseObjectReference.getDocumentReference();

        EntityReference sourceEntityReference;
        if (RulesObjectWriter.XWIKI_PREFERENCES.equals(sourceDocumentReference.getName()) && isGlobalRight) {
            // handle rule update from wiki
            sourceEntityReference = sourceDocumentReference.getWikiReference();
        } else if (RulesObjectWriter.XWIKI_WEB_PREFERENCES.equals(sourceDocumentReference.getName()) && isGlobalRight) {
            // handle rule update from space
            sourceEntityReference = sourceDocumentReference.getLastSpaceReference();
        } else {
            // handle rule update from page
            sourceEntityReference = sourceDocumentReference;
        }

        XWikiDocument currentDocument = (XWikiDocument) source;
        XWikiDocument previousDocument = currentDocument.getOriginalDocument();

        List<ReadableSecurityRule> previousRules = this.getRules(previousDocument, isGlobalRight);
        List<ReadableSecurityRule> currentRules = this.getRules(currentDocument, isGlobalRight);

        List<SecurityRuleDiff> securityRuleDiffs = this.securityRuleAbacus.computeRuleDiff(previousRules, currentRules);
        SecurityReference securityReference = this.securityReferenceFactory.newEntityReference(sourceEntityReference);
        this.observationManager.notify(new RightUpdatedEvent(), securityReference, securityRuleDiffs);
    }

    private List<ReadableSecurityRule> getRules(XWikiDocument document, boolean globalOnly)
    {
        List<ReadableSecurityRule> securityRules = new ArrayList<>();
        WikiReference wikiReference = document.getDocumentReference().getWikiReference();
        EntityReference xClassReference = (globalOnly)
            ? XWikiGlobalRightsDocumentInitializer.CLASS_REFERENCE
            : XWikiRightsDocumentInitializer.CLASS_REFERENCE;

        List<BaseObject> xObjects = document.getXObjects(xClassReference);
        for (BaseObject xObject : xObjects) {
            if (xObject != null) {
                XWikiSecurityRule newRule =
                    XWikiSecurityRule.createNewRule(xObject, this.documentReferenceResolver, wikiReference, false);
                securityRules.add(newRule);
            }
        }
        return securityRules;
    }

}
