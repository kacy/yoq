// store — persistent state facade
//
// this file now exposes the stable state-store API while the
// implementations live in smaller domain modules under `state/store/`.

const common = @import("store/common.zig");

pub const StoreError = common.StoreError;

pub const ContainerRecord = @import("store/containers.zig").ContainerRecord;
pub const ImageRecord = @import("store/images.zig").ImageRecord;
pub const BuildCacheEntry = @import("store/cache.zig").BuildCacheEntry;
pub const ServiceRecord = @import("store/services.zig").ServiceRecord;
pub const ServiceHttpRouteRecord = @import("store/services.zig").ServiceHttpRouteRecord;
pub const ServiceHttpRouteInput = @import("store/services.zig").ServiceHttpRouteInput;
pub const ServiceHttpRouteMethodRecord = @import("store/services.zig").ServiceHttpRouteMethodRecord;
pub const ServiceHttpRouteMethodInput = @import("store/services.zig").ServiceHttpRouteMethodInput;
pub const ServiceHttpRouteHeaderRecord = @import("store/services.zig").ServiceHttpRouteHeaderRecord;
pub const ServiceHttpRouteHeaderInput = @import("store/services.zig").ServiceHttpRouteHeaderInput;
pub const ServiceHttpRouteBackendRecord = @import("store/services.zig").ServiceHttpRouteBackendRecord;
pub const ServiceHttpRouteBackendInput = @import("store/services.zig").ServiceHttpRouteBackendInput;
pub const ServiceEndpointRecord = @import("store/services.zig").ServiceEndpointRecord;
pub const ServiceNameRecord = @import("store/services.zig").ServiceNameRecord;
pub const NetworkPolicyRecord = @import("store/services.zig").NetworkPolicyRecord;
pub const DeploymentRecord = @import("store/deployments.zig").DeploymentRecord;
pub const CronScheduleRecord = @import("store/crons.zig").CronScheduleRecord;
pub const TrainingJobRecord = @import("store/training.zig").TrainingJobRecord;
pub const TrainingJobSummary = @import("store/training.zig").TrainingJobSummary;
pub const CheckpointRecord = @import("store/training.zig").CheckpointRecord;

pub const initTestDb = common.initTestDb;
pub const deinitTestDb = common.deinitTestDb;
pub const getDb = common.getDb;
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

pub const createService = @import("store/services.zig").createService;
pub const ensureService = @import("store/services.zig").ensureService;
pub const syncServiceConfig = @import("store/services.zig").syncServiceConfig;
pub const getService = @import("store/services.zig").getService;
pub const getServiceEndpoint = @import("store/services.zig").getServiceEndpoint;
pub const listServices = @import("store/services.zig").listServices;
pub const upsertServiceEndpoint = @import("store/services.zig").upsertServiceEndpoint;
pub const removeServiceEndpoint = @import("store/services.zig").removeServiceEndpoint;
pub const markServiceEndpointAdminState = @import("store/services.zig").markServiceEndpointAdminState;
pub const listServiceEndpoints = @import("store/services.zig").listServiceEndpoints;
pub const listServiceEndpointsByNode = @import("store/services.zig").listServiceEndpointsByNode;
pub const removeServiceEndpointsByContainer = @import("store/services.zig").removeServiceEndpointsByContainer;
pub const removeServiceEndpointsByNode = @import("store/services.zig").removeServiceEndpointsByNode;
pub const registerServiceName = @import("store/services.zig").registerServiceName;
pub const unregisterServiceName = @import("store/services.zig").unregisterServiceName;
pub const removeServiceNamesByName = @import("store/services.zig").removeServiceNamesByName;
pub const lookupServiceNames = @import("store/services.zig").lookupServiceNames;
pub const lookupServiceAddresses = @import("store/services.zig").lookupServiceAddresses;
pub const listServiceNames = @import("store/services.zig").listServiceNames;
pub const addNetworkPolicy = @import("store/services.zig").addNetworkPolicy;
pub const removeNetworkPolicy = @import("store/services.zig").removeNetworkPolicy;
pub const listNetworkPolicies = @import("store/services.zig").listNetworkPolicies;
pub const getServicePolicies = @import("store/services.zig").getServicePolicies;

pub const saveDeployment = @import("store/deployments.zig").saveDeployment;
pub const saveDeploymentInDb = @import("store/deployments.zig").saveDeploymentInDb;
pub const getDeployment = @import("store/deployments.zig").getDeployment;
pub const getDeploymentInDb = @import("store/deployments.zig").getDeploymentInDb;
pub const listDeployments = @import("store/deployments.zig").listDeployments;
pub const listDeploymentsByApp = @import("store/deployments.zig").listDeploymentsByApp;
pub const listDeploymentsByAppInDb = @import("store/deployments.zig").listDeploymentsByAppInDb;
pub const listLatestDeploymentsByApp = @import("store/deployments.zig").listLatestDeploymentsByApp;
pub const listLatestDeploymentsByAppInDb = @import("store/deployments.zig").listLatestDeploymentsByAppInDb;
pub const updateDeploymentStatus = @import("store/deployments.zig").updateDeploymentStatus;
pub const updateDeploymentStatusInDb = @import("store/deployments.zig").updateDeploymentStatusInDb;
pub const updateDeploymentProgress = @import("store/deployments.zig").updateDeploymentProgress;
pub const updateDeploymentProgressInDb = @import("store/deployments.zig").updateDeploymentProgressInDb;
pub const getLatestDeployment = @import("store/deployments.zig").getLatestDeployment;
pub const getLatestDeploymentByApp = @import("store/deployments.zig").getLatestDeploymentByApp;
pub const getLatestDeploymentByAppInDb = @import("store/deployments.zig").getLatestDeploymentByAppInDb;
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
