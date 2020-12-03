package org.xwiki.contrib.rights;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ReadableSecurityRule;

@Component
@Named("rights")
@Singleton
public class RightsAPIService implements ScriptService
{
    @Inject
    RightsReader rightsReader;

    @Inject
    RightsWriter rightsWriter;

    // TODO: inject a logger & log the operations.

    /**
     * @param ref
     * @return
     */
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        return rightsReader.getActualRules(ref);
    }

    /**
     * @param ref
     * @param withImplied
     * @return
     */
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        return rightsReader.getRules(ref, withImplied);
    }

    /**
     * @param ref
     * @return
     */
    public List<ReadableSecurityRule> getPersistedRules(EntityReference ref)
    {
        return rightsReader.getPersistedRules(ref);
    }
}
