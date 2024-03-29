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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.GroupSecurityReference;
import org.xwiki.security.UserSecurityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;
import org.xwiki.text.XWikiToStringStyle;

import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.GroupsClass;
import com.xpn.xwiki.objects.classes.LevelsClass;
import com.xpn.xwiki.objects.classes.UsersClass;

/**
 * Wrapper around xwiki rights objects to convert them into security rules.
 * <p>
 * This class is copied from {@link org.xwiki.security.authorization.internal.XWikiSecurityRule} at version
 * 2a235705f6b0144820af3fd8cd9b9366c63feff7 and modified in order to implement {@link
 * org.xwiki.security.authorization.ReadableSecurityRule}.
 *
 * @version $Id$
 */
public class XWikiSecurityRule implements ReadableSecurityRule
{
    /**
     * The set of users.
     */
    private final Set<DocumentReference> users = new HashSet<DocumentReference>();

    /**
     * The set of groups.
     */
    private final Set<DocumentReference> groups = new HashSet<DocumentReference>();

    /**
     * The set of right levels.
     */
    private final RightSet rights = new RightSet();

    /**
     * The state specified by this object.
     */
    private final RuleState state;

    /**
     * True if the rule is persisted in an object (eg. XObject). Otherwise, false
     */
    private final boolean isPersisted;

    /**
     * Constructor to be used for implied rules. By default, the rule is not marked as persisted.
     *
     * @param rights The set of rights.
     * @param state The state of this rights object.
     * @param users The set of users.
     * @param groups The set of groups.
     */
    protected XWikiSecurityRule(Set<Right> rights, RuleState state, Collection<DocumentReference> users,
        Collection<DocumentReference> groups)
    {
        this(rights, state, users, groups, false);
    }

    /**
     * Constructor to use for general rules.
     *
     * @param rights The set of rights.
     * @param state The state of this rights object.
     * @param users The set of users.
     * @param groups The set of groups.
     * @param isPersisted if true, the rule is marked as persisted in an object (XObject). Otherwise, false.
     */
    protected XWikiSecurityRule(Set<Right> rights, RuleState state, Collection<DocumentReference> users,
        Collection<DocumentReference> groups, boolean isPersisted)
    {
        if (users != null) {
            this.users.addAll(users);
        }
        if (groups != null) {
            this.groups.addAll(groups);
        }
        if (rights != null) {
            this.rights.addAll(rights);
        }
        this.state = state;
        this.isPersisted = isPersisted;
    }

    /**
     * Construct a more manageable java object from the corresponding xwiki object.
     *
     * @param obj An xwiki rights object.
     * @param resolver A document reference resolver for user and group pages.
     * @param wikiReference A reference to the wiki from which these rules are extracted.
     * @param disableEditRight when true, edit right is disregarded while building this rule.
     * @throws IllegalArgumentException if the source object for the rules is badly formed.
     */
    private XWikiSecurityRule(BaseObject obj, DocumentReferenceResolver<String> resolver,
        WikiReference wikiReference, boolean disableEditRight)
    {
        state = (obj.getIntValue(XWikiConstants.ALLOW_FIELD_NAME) == 1) ? RuleState.ALLOW : RuleState.DENY;

        // By default, the current rule is marked as persistent because it's coming from the {@link BaseObject} given
        // as parameter (a persisted one).
        this.isPersisted = true;

        for (String level : LevelsClass.getListFromString(obj.getStringValue(XWikiConstants.LEVELS_FIELD_NAME))) {
            Right right = Right.toRight(level);
            if (right != Right.ILLEGAL && (!disableEditRight || right != Right.EDIT)) {
                rights.add(right);
            }
        }

        // No need to computes users when no right will match.
        if (rights.size() > 0) {
            for (String user : UsersClass.getListFromString(obj.getStringValue(XWikiConstants.USERS_FIELD_NAME))) {
                if (StringUtils.isBlank(user)) {
                    continue;
                }
                DocumentReference ref = resolver.resolve(user, wikiReference);
                if (XWikiConstants.GUEST_USER.equals(ref.getName())) {
                    // In the database, Rights for public users (not logged in) are stored using a user named
                    // XWikiGuest, while in SecurityUserReference the original reference for those users is null. So,
                    // store rules for XWikiGuest to be matched by null.
                    ref = null;
                }
                this.users.add(ref);
            }

            for (String group : GroupsClass.getListFromString(obj.getStringValue(XWikiConstants.GROUPS_FIELD_NAME))) {
                if (StringUtils.isBlank(group)) {
                    continue;
                }
                DocumentReference ref = resolver.resolve(group, wikiReference);
                this.groups.add(ref);
            }
        }
    }

    @Override
    public boolean match(Right right)
    {
        return rights.contains(right);
    }

    @Override
    public boolean match(GroupSecurityReference group)
    {
        return groups.contains(group.getOriginalReference());
    }

    @Override
    public boolean match(UserSecurityReference user)
    {
        return users.contains(user.getOriginalReference());
    }

    @Override
    public RuleState getState()
    {
        return state;
    }

    @Override
    public List<DocumentReference> getUsers()
    {
        return new ArrayList<>(users);
    }

    @Override
    public List<DocumentReference> getGroups()
    {
        return new ArrayList<>(groups);
    }

    @Override
    public RightSet getRights()
    {
        return rights;
    }

    @Override
    public boolean isPersisted()
    {
        return isPersisted;
    }

    @Override
    public boolean equals(Object object)
    {
        if (object == this) {
            return true;
        }
        if (object == null || object.getClass() != getClass()) {
            return false;
        }

        XWikiSecurityRule other = (XWikiSecurityRule) object;

        return state == other.state
            && rights.equals(other.rights)
            && users.equals(other.users)
            && groups.equals(other.groups);
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder()
            .append(state)
            .append(rights)
            .append(users)
            .append(groups)
            .toHashCode();
    }

    @Override
    public String toString()
    {
        ToStringBuilder builder = new ToStringBuilder(this, new XWikiToStringStyle());

        return builder
            .append("State", state)
            .append("Rights", rights)
            .append("Users", users)
            .append("Groups", groups)
            .toString();
    }

    /**
     * Create and return a new Security rule, marked as persisted, based on an existing BaseObject.
     *
     * @param obj An xwiki rights object.
     * @param resolver A document reference resolver for user and group pages.
     * @param wikiReference A reference to the wiki from which these rules are extracted.
     * @param disableEditRight when true, edit right is disregarded while building this rule.
     * @return a newly created security rule, marked as persisted (since it's based on the given BaseObject parameter)
     * @throws IllegalArgumentException if the source object for the rules is badly formed.
     */
    static XWikiSecurityRule createNewRule(BaseObject obj, DocumentReferenceResolver<String> resolver,
        WikiReference wikiReference, boolean disableEditRight) throws IllegalArgumentException
    {
        XWikiSecurityRule rule = new XWikiSecurityRule(obj, resolver, wikiReference, disableEditRight);

        if (rule.rights.size() == 0) {
            throw new IllegalArgumentException("No rights to build this rule.");
        }

        if (rule.users.size() == 0 && rule.groups.size() == 0) {
            throw new IllegalArgumentException("No user/group to build this rule.");
        }

        return rule;
    }
}
