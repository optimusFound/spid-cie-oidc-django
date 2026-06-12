import logging

from django.contrib import admin
from django.utils.safestring import mark_safe
from django.contrib import messages

# from prettyjson import PrettyJSONWidget

from django.conf import settings
from .jwtse import unpad_jwt_payload
from .statements import EntityConfiguration, get_entity_configurations, get_entity_statements
from .models import (
    FederationEntityConfiguration,
    FederationHistoricalKey,
    FetchedEntityStatement,
    TrustChain,
    StaffToken
)
from spid_cie_oidc.entity.trust_chain_operations import get_or_create_trust_chain

from . settings import HTTPC_PARAMS

logger = logging.getLogger(__name__)
from urllib.parse import urlencode

@admin.register(FederationHistoricalKey)
class FederationHistoricalKey(admin.ModelAdmin):
    readonly_fields = ('jwk', "as_json")
    list_display = ("entity", "kid", "inactive_from")
    list_filter = ("created", "modified", "inactive_from")
    search_fields = ("entity",)


@admin.register(FederationEntityConfiguration)
class FederationEntityConfigurationAdmin(admin.ModelAdmin):
    # formfield_overrides = {
    # JSONField: {
    # "widget": PrettyJSONWidget(
    # attrs={"initial": "parsed", "disabled": True}
    # )
    # }
    # }

    @admin.action(description="update trust marks")
    def update_trust_marks(modeladmin, request, queryset):  # pragma: no cover
        """
        Fetch trust marks from all configured authorities.
        """

        for obj in queryset:
            trust_marks = {}

            jwts = get_entity_configurations(obj.authority_hints, HTTPC_PARAMS)

            for jwt in jwts:
                try:
                    ec = EntityConfiguration(jwt, httpc_params=HTTPC_PARAMS)
                except Exception as exc:
                    msg = f"Failed getting Entity Configuration for {jwt}: {exc}"
                    logger.exception(msg)
                    modeladmin.message_user(request, msg, level=messages.ERROR)
                    continue

                try:
                    fetch_api_url = ec.payload["metadata"]["federation_entity"][
                        "federation_fetch_endpoint"
                    ]
                except KeyError:
                    msg = (
                        "Missing federation_fetch_endpoint in federation_entity "
                        f"metadata for {obj.sub} by {ec.sub}."
                    )
                    logger.warning(msg)
                    modeladmin.message_user(request, msg, level=messages.ERROR)
                    continue

                url = f"{fetch_api_url}?{urlencode({'sub': obj.sub})}"

                try:
                    logger.info("Getting entity statements from %s", url)
                    entity_statement_jwts = get_entity_statements([url], HTTPC_PARAMS)

                    if not entity_statement_jwts:
                        msg = f"No entity statements returned from {url}"
                        logger.warning(msg)
                        modeladmin.message_user(request, msg, level=messages.ERROR)
                        continue

                    payload = unpad_jwt_payload(entity_statement_jwts[0])

                    for trust_mark in payload.get("trust_marks", []):
                        if not isinstance(trust_mark, dict):
                            logger.warning("Invalid trust mark item: %r", trust_mark)
                            continue

                        trust_mark_id = trust_mark.get("id")
                        trust_mark_jwt = trust_mark.get("trust_mark")

                        if not trust_mark_id or not trust_mark_jwt:
                            logger.warning("Incomplete trust mark item: %r", trust_mark)
                            continue

                        trust_marks[trust_mark_id] = trust_mark_jwt

                except Exception as exc:
                    msg = f"Error getting entity statements from {url}: {exc}"
                    logger.exception(msg)
                    modeladmin.message_user(request, msg, level=messages.ERROR)
                    continue

            obj.trust_marks = trust_marks
            obj.save(update_fields=["trust_marks"])

            msg = f"Updated {len(trust_marks)} trust mark(s) for {obj.sub}"
            modeladmin.message_user(request, msg, level=messages.SUCCESS)

    list_display = (
        "sub",
        "type",
        "kids",
        "is_active",
        "created",
    )
    list_filter = ("created", "modified", "is_active")
    # search_fields = ('command__name',)
    readonly_fields = (
        "created",
        "modified",
        "entity_configuration_as_json",
        "pems_as_html",
        "kids",
        "type",
    )
    actions = [update_trust_marks]

    def pems_as_html(self, obj):
        res = ""
        data = dict()
        for k, v in obj.pems_as_dict.items():
            data[k] = {}
            for i in ("public", "private"):
                data[k][i] = v[i].replace("\n", "<br>")
            res += (
                f"<b>{k}</b><br><br>"
                f"{data[k]['public']}<br>"
                f"{data[k]['private']}<br><hr>"
            )
        return mark_safe(res)  # nosec


@admin.register(TrustChain)
class TrustChainAdmin(admin.ModelAdmin):

    @admin.action(description='reload trust chain')
    def update_trust_chain(modeladmin, request, queryset): # pragma: no cover
        for tc in queryset:
            sub = tc.sub
            ta = tc.trust_anchor.sub
            try :
                get_or_create_trust_chain(
                    subject=sub,
                    trust_anchor=ta,
                    httpc_params=settings.HTTPC_PARAMS,
                    required_trust_marks=getattr(
                        settings, "OIDCFED_REQUIRED_TRUST_MARKS", [],
                    ),
                    force=True
                )
                messages.success(
                    request, f"Trust chain successfully reloaded for {sub}"
                )
            except Exception as e:
                messages.error(request, f"Failed to update {sub} due to: {e}")
                continue

    list_display = ("sub", "exp", "modified", "is_valid")
    list_filter = ("exp", "modified", "is_active")
    search_fields = ("sub",)
    readonly_fields = (
        "created",
        "modified",
        "parties_involved",
        "status",
        "log",
        "chain",
        "iat",
    )
    actions = [update_trust_chain]


@admin.register(FetchedEntityStatement)
class FetchedEntityStatementAdmin(admin.ModelAdmin):
    list_display = ("sub", "iss", "exp", "iat", "created", "modified")
    list_filter = ("created", "modified", "exp", "iat")
    search_fields = ("sub", "iss")
    readonly_fields = ("sub", "statement", "created", "modified", "iat", "exp", "iss")


@admin.register(StaffToken)
class StaffTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "expire_at", "is_valid")
    list_filter = ("created", "modified", "expire_at")
    search_fields = ("token", )
    readonly_fields = ("is_valid",)
    raw_id_fields = ('user',)
