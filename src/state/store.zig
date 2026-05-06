// store — persistent state facade
//
// this file now exposes the stable state-store API while the
// implementations live in smaller domain modules under `state/store/`.

const common = @import("store/common.zig");
const service_core = @import("store/services_core.zig");
const service_endpoint_types = @import("store/services_endpoint_types.zig");
const service_endpoints = @import("store/services_endpoints.zig");
const service_name_types = @import("store/services_name_types.zig");
const service_names = @import("store/services_names.zig");
const service_policies = @import("store/services_policies.zig");
const service_policy_types = @import("store/services_policy_types.zig");
const service_types = @import("store/services_types.zig");

pub const StoreError = common.StoreError;

pub const ContainerRecord = @import("store/containers.zig").ContainerRecord;
pub const ImageRecord = @import("store/images.zig").ImageRecord;
pub const BuildCacheEntry = @import("store/cache.zig").BuildCacheEntry;
pub const ServiceRecord = service_types.ServiceRecord;
pub const ServiceHttpRouteRecord = service_types.ServiceHttpRouteRecord;
pub const ServiceHttpRouteInput = service_types.ServiceHttpRouteInput;
pub const ServiceHttpRouteMethodRecord = service_types.ServiceHttpRouteMethodRecord;
pub const ServiceHttpRouteMethodInput = service_types.ServiceHttpRouteMethodInput;
pub const ServiceHttpRouteHeaderRecord = service_types.ServiceHttpRouteHeaderRecord;
pub const ServiceHttpRouteHeaderInput = service_types.ServiceHttpRouteHeaderInput;
pub const ServiceHttpRouteBackendRecord = service_types.ServiceHttpRouteBackendRecord;
pub const ServiceHttpRouteBackendInput = service_types.ServiceHttpRouteBackendInput;
pub const ServiceEndpointRecord = service_endpoint_types.ServiceEndpointRecord;
pub const ServiceNameRecord = service_name_types.ServiceNameRecord;
pub const NetworkPolicyRecord = service_policy_types.NetworkPolicyRecord;
pub const DeploymentRecord = @import("store/deployments.zig").DeploymentRecord;
pub const CronScheduleRecord = @import("store/crons.zig").CronScheduleRecord;
pub const TrainingJobRecord = @import("store/training.zig").TrainingJobRecord;
pub const TrainingJobSummary = @import("store/training.zig").TrainingJobSummary;
pub const CheckpointRecord = @import("store/training.zig").CheckpointRecord;

pub const initTestDb = common.initTestDb;
pub const deinitTestDb = common.deinitTestDb;
pub const closeDb = common.closeDb;
pub const openDb = common.openDb;

pub const save = @import("store/containers.zig").save;
pub const load = @import("store/containers.zig").load;
pub const findByHostname = @import("store/containers.zig").findByHostname;
pub const remove = @import("store/containers.zig").remove;
pub const listIds = @import("store/containers.zig").listIds;
pub const updateStatus = @import("store/containers.zig").updateStatus;
pub const updateNetwork = @import("store/containers.zig").updateNetwork;
pub const listAppContainerIds = @import("store/containers.zig").listAppContainerIds;
pub const findAppContainer = @import("store/containers.zig").findAppContainer;
pub const listAll = @import("store/containers.zig").listAll;

pub const saveImage = @import("store/images.zig").saveImage;
pub const loadImage = @import("store/images.zig").loadImage;
pub const findImage = @import("store/images.zig").findImage;
pub const listImages = @import("store/images.zig").listImages;
pub const removeImage = @import("store/images.zig").removeImage;

pub const lookupBuildCache = @import("store/cache.zig").lookupBuildCache;
pub const storeBuildCache = @import("store/cache.zig").storeBuildCache;
pub const listBuildCacheDigests = @import("store/cache.zig").listBuildCacheDigests;

pub const createService = service_core.create;
pub const ensureService = service_core.ensure;
pub const syncServiceConfig = service_core.syncConfig;
pub const getService = service_core.get;
pub const listServices = service_core.list;
pub const getServiceEndpoint = service_endpoints.get;
pub const upsertServiceEndpoint = service_endpoints.upsert;
pub const removeServiceEndpoint = service_endpoints.remove;
pub const markServiceEndpointAdminState = service_endpoints.markAdminState;
pub const listServiceEndpoints = service_endpoints.list;
pub const listServiceEndpointsByNode = service_endpoints.listByNode;
pub const removeServiceEndpointsByContainer = service_endpoints.removeByContainer;
pub const removeServiceEndpointsByNode = service_endpoints.removeByNode;
pub const registerServiceName = service_names.register;
pub const unregisterServiceName = service_names.unregister;
pub const removeServiceNamesByName = service_names.removeByName;
pub const lookupServiceNames = service_names.lookupNames;
pub const lookupServiceAddresses = service_names.lookupAddresses;
pub const listServiceNames = service_names.list;
pub const addNetworkPolicy = service_policies.add;
pub const removeNetworkPolicy = service_policies.remove;
pub const listNetworkPolicies = service_policies.list;
pub const getServicePolicies = service_policies.listForSource;

pub const saveDeployment = @import("store/deployments.zig").saveDeployment;
pub const saveDeploymentInDb = @import("store/deployments.zig").saveDeploymentInDb;
pub const getDeployment = @import("store/deployments.zig").getDeployment;
pub const getDeploymentInDb = @import("store/deployments.zig").getDeploymentInDb;
pub const listDeployments = @import("store/deployments.zig").listDeployments;
pub const listDeploymentsByApp = @import("store/deployments.zig").listDeploymentsByApp;
pub const listDeploymentsByAppInDb = @import("store/deployments.zig").listDeploymentsByAppInDb;
pub const listLatestDeploymentsByApp = @import("store/deployments.zig").listLatestDeploymentsByApp;
pub const listLatestDeploymentsByAppInDb = @import("store/deployments.zig").listLatestDeploymentsByAppInDb;
pub const listRecoverableActiveDeploymentsByApp = @import("store/deployments.zig").listRecoverableActiveDeploymentsByApp;
pub const listRecoverableActiveDeploymentsByAppInDb = @import("store/deployments.zig").listRecoverableActiveDeploymentsByAppInDb;
pub const updateDeploymentStatus = @import("store/deployments.zig").updateDeploymentStatus;
pub const updateDeploymentStatusInDb = @import("store/deployments.zig").updateDeploymentStatusInDb;
pub const updateDeploymentProgress = @import("store/deployments.zig").updateDeploymentProgress;
pub const updateDeploymentProgressInDb = @import("store/deployments.zig").updateDeploymentProgressInDb;
pub const updateDeploymentRolloutControlState = @import("store/deployments.zig").updateDeploymentRolloutControlState;
pub const updateDeploymentRolloutControlStateInDb = @import("store/deployments.zig").updateDeploymentRolloutControlStateInDb;
pub const updateDeploymentSupersededByReleaseId = @import("store/deployments.zig").updateDeploymentSupersededByReleaseId;
pub const updateDeploymentSupersededByReleaseIdInDb = @import("store/deployments.zig").updateDeploymentSupersededByReleaseIdInDb;
pub const getLatestDeployment = @import("store/deployments.zig").getLatestDeployment;
pub const getLatestDeploymentByApp = @import("store/deployments.zig").getLatestDeploymentByApp;
pub const getLatestDeploymentByAppInDb = @import("store/deployments.zig").getLatestDeploymentByAppInDb;
pub const getActiveDeploymentByApp = @import("store/deployments.zig").getActiveDeploymentByApp;
pub const getActiveDeploymentByAppInDb = @import("store/deployments.zig").getActiveDeploymentByAppInDb;
pub const getLastSuccessfulDeployment = @import("store/deployments.zig").getLastSuccessfulDeployment;
pub const getLastSuccessfulDeploymentByApp = @import("store/deployments.zig").getLastSuccessfulDeploymentByApp;
pub const getPreviousSuccessfulDeploymentByApp = @import("store/deployments.zig").getPreviousSuccessfulDeploymentByApp;
pub const getPreviousSuccessfulDeploymentByAppInDb = @import("store/deployments.zig").getPreviousSuccessfulDeploymentByAppInDb;
pub const getRollbackTargetDeploymentByApp = @import("store/deployments.zig").getRollbackTargetDeploymentByApp;
pub const getRollbackTargetDeploymentByAppInDb = @import("store/deployments.zig").getRollbackTargetDeploymentByAppInDb;

pub const replaceCronSchedulesForApp = @import("store/crons.zig").replaceCronSchedulesForApp;
pub const replaceCronSchedulesForAppInDb = @import("store/crons.zig").replaceCronSchedulesForAppInDb;
pub const listCronSchedulesByApp = @import("store/crons.zig").listCronSchedulesByApp;
pub const listCronSchedulesByAppInDb = @import("store/crons.zig").listCronSchedulesByAppInDb;

pub const saveTrainingJob = @import("store/training.zig").saveTrainingJob;
pub const saveTrainingJobInDb = @import("store/training.zig").saveTrainingJobInDb;
pub const updateTrainingJobState = @import("store/training.zig").updateTrainingJobState;
pub const updateTrainingJobStateInDb = @import("store/training.zig").updateTrainingJobStateInDb;
pub const incrementTrainingJobRestarts = @import("store/training.zig").incrementTrainingJobRestarts;
pub const incrementTrainingJobRestartsInDb = @import("store/training.zig").incrementTrainingJobRestartsInDb;
pub const updateTrainingJobGpus = @import("store/training.zig").updateTrainingJobGpus;
pub const updateTrainingJobGpusInDb = @import("store/training.zig").updateTrainingJobGpusInDb;
pub const findTrainingJob = @import("store/training.zig").findTrainingJob;
pub const findTrainingJobInDb = @import("store/training.zig").findTrainingJobInDb;
pub const getTrainingJob = @import("store/training.zig").getTrainingJob;
pub const getTrainingJobInDb = @import("store/training.zig").getTrainingJobInDb;
pub const listTrainingJobsByApp = @import("store/training.zig").listTrainingJobsByApp;
pub const listTrainingJobsByAppInDb = @import("store/training.zig").listTrainingJobsByAppInDb;
pub const summarizeTrainingJobsByApp = @import("store/training.zig").summarizeTrainingJobsByApp;
pub const summarizeTrainingJobsByAppInDb = @import("store/training.zig").summarizeTrainingJobsByAppInDb;
pub const saveCheckpoint = @import("store/training.zig").saveCheckpoint;
pub const getLatestCheckpoint = @import("store/training.zig").getLatestCheckpoint;
pub const listCheckpoints = @import("store/training.zig").listCheckpoints;
pub const deleteCheckpoint = @import("store/training.zig").deleteCheckpoint;
